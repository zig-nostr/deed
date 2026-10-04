#
# deed - one-line installer for Windows.
#
#   irm https://raw.githubusercontent.com/zig-nostr/deed/main/scripts/install.ps1 | iex
#
# The PowerShell counterpart of install.sh. Downloads the Windows release build,
# verifies it against the SHA-256 published beside it, unpacks it into
# %LOCALAPPDATA%\deed and adds that folder to the user PATH. No administrator
# rights, nothing outside your own profile, and nothing is installed that did
# not verify.
#
# Options, when the script runs as a file:
#
#   .\install.ps1 -Version v0.4.1 -Prefix C:\tools\deed
#
# A piped run has no command line to put them on, so it reads the same options
# from the environment:
#
#   $env:DEED_VERSION = 'v0.4.1'
#   irm https://raw.githubusercontent.com/zig-nostr/deed/main/scripts/install.ps1 | iex
#
# or takes them when the download is run as a script block:
#
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/zig-nostr/deed/main/scripts/install.ps1))) -Version v0.4.1
#
# An option given on the command line wins over the environment.
#
# There is no param() block at the top, on purpose. `irm | iex` hands this file
# to Invoke-Expression as one string, where a top-level param() is a parameter
# list for nothing. Everything runs inside one script block instead, called with
# whatever the file was called with. That also keeps the helpers and variables
# below out of the session a piped run executes in, which is the reader's own.
#
# This file is deliberately pure ASCII. Windows PowerShell 5.1 reads a script
# that has no byte order mark in the machine's legacy code page, so any other
# character arrives as something else. CI fails on any byte above 0x7F in here.
# For the same reason of reach it keeps to syntax 5.1 understands: that is the
# PowerShell every Windows machine has.
#
& {
    [CmdletBinding()]
    param(
        [string]$Version,
        [string]$Prefix,
        [string]$Archive,
        [switch]$Help
    )

    # Scoped to this block, so a piped run leaves the session's own settings as
    # they were.
    $ErrorActionPreference = 'Stop'
    # Windows PowerShell 5.1 redraws its progress bar for every chunk a download
    # receives, which turns a two-megabyte download into a long wait.
    $ProgressPreference = 'SilentlyContinue'

    if (-not $Version) { $Version = $env:DEED_VERSION }
    if (-not $Prefix) { $Prefix = $env:DEED_PREFIX }
    if (-not $Archive) { $Archive = $env:DEED_ARCHIVE }

    $repo = 'zig-nostr/deed'

    # A file run can end with an exit status. A piped run executes inside the
    # reader's own session, where `exit` would close their terminal, so there a
    # failure is raised as an error instead. That still stops the run, and still
    # makes `powershell -Command` exit non-zero.
    $fromFile = [bool]$PSCommandPath

    # A hashtable rather than a variable, so the functions below can record the
    # temporary directory where the cleanup at the end can see it.
    $state = @{ Work = $null }

    $usage = @'
deed installer for Windows

  irm https://raw.githubusercontent.com/zig-nostr/deed/main/scripts/install.ps1 | iex
  .\install.ps1 [options]

Options:
  -Version <vX.Y.Z>  install this release instead of the latest
  -Prefix <dir>      install into <dir> (default: %LOCALAPPDATA%\deed)
  -Archive <file>    install from a zip already on disk, skipping the
                     download. Its .sha256 is still required, beside it.
  -Help              this text

A piped run reads the same options from $env:DEED_VERSION,
$env:DEED_PREFIX and $env:DEED_ARCHIVE.

Installs deed.exe into <dir> and adds <dir> to your user PATH.
Nothing needs administrator rights.
'@

    function Say([string]$msg) { Write-Host "==> $msg" }
    function Warn([string]$msg) { Write-Host "note: $msg" }
    function Fail([string]$msg) { throw $msg }

    # A path as the reader meant it: relative to where they are, and allowed
    # not to exist yet.
    function Resolve-UserPath([string]$path) {
        $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path)
    }

    # The HTTP status behind a failed request, or 0 when there was no answer at
    # all. 5.1 and 7 raise different exception types, and both carry the status
    # on .Response.
    function Get-Status($err) {
        $resp = $err.Exception.Response
        if ($resp -and $resp.StatusCode) { return [int]$resp.StatusCode }
        return 0
    }

    # Which build this machine wants.
    #
    # There is no ARM build for Windows. Windows 11 on ARM runs x86_64 programs
    # under its own emulation, and the x86_64 build is the one every release is
    # checked on, so ARM64 machines get that.
    function Get-Platform {
        if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
            Fail 'this script installs the Windows build. On macOS and Linux, run: curl -fsSL https://raw.githubusercontent.com/zig-nostr/deed/main/scripts/install.sh | bash'
        }
        # A 32-bit PowerShell on a 64-bit Windows reports x86 here and the real
        # architecture in PROCESSOR_ARCHITEW6432.
        $arch = $env:PROCESSOR_ARCHITEW6432
        if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
        switch ($arch) {
            'AMD64' { return 'windows-x86_64' }
            'ARM64' { return 'windows-x86_64' }
            default { Fail "no deed build for '$arch'. The published Windows build is x86_64, which also runs on ARM64." }
        }
    }

    # The tag of the newest published release, from the same API answer
    # install.sh reads.
    function Get-LatestTag {
        $api = "https://api.github.com/repos/$repo/releases/latest"
        try {
            $release = Invoke-RestMethod -Uri $api -UseBasicParsing
        } catch {
            $code = Get-Status $_
            switch ($code) {
                0 { Fail 'could not reach GitHub. Check your connection and try again.' }
                403 { Fail 'GitHub rate-limited this machine. Wait a few minutes, or name a release with -Version or $env:DEED_VERSION.' }
                429 { Fail 'GitHub rate-limited this machine. Wait a few minutes, or name a release with -Version or $env:DEED_VERSION.' }
                404 { Fail "no published release found for $repo." }
                default { Fail "GitHub answered $code." }
            }
        }
        $tag = [string]$release.tag_name
        if (-not $tag) { Fail "could not read the release tag from GitHub's answer." }
        return $tag
    }

    # Verifies a zip against the digest published beside it.
    #
    # The digest is read from the .sha256 file that sits next to the artifact,
    # not out of an API response, so there is no list to pick the wrong entry
    # out of.
    function Assert-Digest([string]$file, [string]$sidecar, [string]$name) {
        $text = Get-Content -Raw -LiteralPath $sidecar
        $want = @(([string]$text).Trim() -split '\s+' | Where-Object { $_ })
        # An empty expected digest compares equal to an empty computed one, and
        # the check then reports success over nothing at all. Both sides have to
        # exist before either is trusted.
        if ($want.Count -eq 0) { Fail "the published SHA-256 for $name is empty. Not installing it." }
        $got = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        if (-not $got) { Fail 'could not compute the SHA-256 of the download. Not installing it.' }
        # Get-FileHash prints capitals and the .sha256 files carry lower case.
        if ($want[0].ToLowerInvariant() -ne $got.ToLowerInvariant()) {
            Fail "$name does not match its published SHA-256. Not installing it."
        }
    }

    # What `deed version` prints, or nothing when the binary will not run. A
    # wrong-architecture binary throws rather than exiting, so both are caught.
    function Get-Reported([string]$exe) {
        $ErrorActionPreference = 'Continue'
        try {
            $out = & $exe version 2>$null
            if ($LASTEXITCODE -ne 0) { return $null }
            return [string]($out | Select-Object -First 1)
        } catch {
            return $null
        }
    }

    # Adds a folder to the user PATH unless it is there already. Returns whether
    # it changed anything.
    #
    # The registry value is read and written as it is stored. The obvious
    # [Environment]::GetEnvironmentVariable('Path', 'User') returns it with every
    # %VARIABLE% already expanded, and writing that back replaces each reference
    # with what it happens to mean today, and turns the value into a plain
    # string.
    function Add-UserPath([string]$dir) {
        $want = $dir.TrimEnd('\')
        $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
        try {
            $raw = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            foreach ($entry in ($raw -split ';')) {
                $have = [Environment]::ExpandEnvironmentVariables($entry.Trim()).TrimEnd('\')
                # -eq ignores case, as Windows paths do.
                if ($have -and $have -eq $want) { return $false }
            }
            $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
            if ($key.GetValueNames() -contains 'Path') {
                $existing = $key.GetValueKind('Path')
                if ($existing -eq [Microsoft.Win32.RegistryValueKind]::String) { $kind = $existing }
            }
            $new = $dir
            if ($raw.Trim()) { $new = $raw.TrimEnd(';') + ';' + $dir }
            $key.SetValue('Path', $new, $kind)
        } finally {
            $key.Close()
        }
        # Writing the registry tells nobody. SetEnvironmentVariable announces the
        # change to running programs, so Explorer, and the terminals it opens,
        # pick up the new PATH. A throwaway variable is set and removed to make
        # that announcement.
        [Environment]::SetEnvironmentVariable('DEED_INSTALL_PATH_REFRESH', '1', 'User')
        [Environment]::SetEnvironmentVariable('DEED_INSTALL_PATH_REFRESH', $null, 'User')
        return $true
    }

    function Install-Deed {
        $platform = Get-Platform

        # Windows PowerShell 5.1 on an older .NET offers only TLS 1.0 and 1.1
        # unless told otherwise, and GitHub accepts neither. SystemDefault (0)
        # already lets the system choose, which includes 1.2.
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            $current = [int][Net.ServicePointManager]::SecurityProtocol
            if ($current -ne 0 -and ($current -band [int][Net.SecurityProtocolType]::Tls12) -eq 0) {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            }
        }

        if ($Prefix) {
            $dest = Resolve-UserPath $Prefix
        } elseif ($env:LOCALAPPDATA) {
            $dest = Join-Path $env:LOCALAPPDATA 'deed'
        } else {
            Fail 'LOCALAPPDATA is not set, so there is no default place to install. Pass -Prefix.'
        }

        $work = Join-Path ([IO.Path]::GetTempPath()) ('deed-install-' + [guid]::NewGuid().ToString('N'))
        try {
            New-Item -ItemType Directory -Path $work | Out-Null
        } catch {
            Fail 'could not make a temporary directory.'
        }
        $state.Work = $work
        $zip = Join-Path $work 'deed.zip'

        if ($Archive) {
            $file = Resolve-UserPath $Archive
            $name = Split-Path -Leaf $file
            if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { Fail "no such file: $Archive" }
            if (-not (Test-Path -LiteralPath "$file.sha256" -PathType Leaf)) { Fail "$Archive.sha256 is missing. Download it beside the zip." }
            # The copy is what gets verified and unpacked, so the bytes checked
            # are the bytes installed.
            Copy-Item -LiteralPath $file -Destination $zip
            Say "Verifying $name..."
            Assert-Digest $zip "$file.sha256" $name
        } else {
            $tag = $Version
            if (-not $tag) { $tag = Get-LatestTag }
            if ($tag -cnotlike 'v*') { Fail "a release tag looks like v0.1.0. Got '$tag'." }
            $name = "deed-$($tag.Substring(1))-$platform.zip"
            $url = "https://github.com/$repo/releases/download/$tag/$name"

            Say "Downloading $name..."
            try {
                Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
            } catch {
                Fail "download failed. There may be no $platform build for $tag."
            }

            # Required, not best effort. A verification step that any transient
            # failure switches off is not a verification step, and every
            # published release has one of these beside every artifact.
            $fetched = $false
            for ($i = 0; $i -lt 3 -and -not $fetched; $i++) {
                try {
                    Invoke-WebRequest -Uri "$url.sha256" -OutFile "$zip.sha256" -UseBasicParsing
                    $fetched = $true
                } catch {
                    Start-Sleep -Seconds 1
                }
            }
            if (-not $fetched) { Fail "could not fetch the published SHA-256 for $name, so the download cannot be verified. Not installing it." }

            Say 'Verifying...'
            Assert-Digest $zip "$zip.sha256" $name
        }
        Say 'SHA-256 verified.'

        $unpacked = Join-Path $work 'unpacked'
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [IO.Compression.ZipFile]::ExtractToDirectory($zip, $unpacked)
        } catch {
            Fail 'the archive could not be unpacked. The download may be incomplete.'
        }
        $exe = Join-Path $unpacked 'deed.exe'
        if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { Fail 'the archive did not contain deed.exe.' }

        # Run it before it replaces anything. An install that reports success
        # without ever executing the binary is how a wrong-architecture build,
        # or an archive holding only a licence, gets called a success, and
        # checking first leaves a working older copy in place.
        $reported = Get-Reported $exe
        if (-not $reported) { Fail 'deed.exe will not run on this machine. Nothing was installed.' }

        Say "Installing into $dest..."
        try {
            New-Item -ItemType Directory -Force -Path $dest | Out-Null
        } catch {
            Fail "could not create $dest."
        }
        try {
            Get-ChildItem -LiteralPath $unpacked -File | Copy-Item -Destination $dest -Force
        } catch {
            Fail "could not write to $dest. If deed is running, close it and try again, or pass -Prefix to install somewhere you own."
        }
        Say "Installed $reported to $(Join-Path $dest 'deed.exe')"

        try {
            if (Add-UserPath $dest) {
                Say "Added $dest to your user PATH."
            } else {
                Say "$dest is already on your user PATH."
            }
        } catch {
            Warn "could not add $dest to your user PATH: $($_.Exception.Message) Add it yourself, or run deed from there."
            return
        }
        Say 'Open a new terminal and run: deed version'
    }

    $failure = $null
    try {
        if ($Help) {
            Write-Host $usage
        } else {
            Install-Deed
        }
    } catch {
        $failure = $_.Exception.Message
    } finally {
        if ($state.Work) { Remove-Item -LiteralPath $state.Work -Recurse -Force -ErrorAction SilentlyContinue }
    }

    if ($failure) {
        if ($fromFile) {
            [Console]::Error.WriteLine("error: $failure")
            exit 1
        }
        $record = New-Object Management.Automation.ErrorRecord (New-Object Exception "error: $failure"), 'DeedInstallFailed', ([Management.Automation.ErrorCategory]::NotSpecified), $null
        $PSCmdlet.ThrowTerminatingError($record)
    }
} @args
