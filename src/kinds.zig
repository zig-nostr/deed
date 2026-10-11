//! The event kinds from the "Event Kinds" table in the NIPs README, plus the
//! kinds deed itself signs or reads (NIP-98, NIP-46, Blossom, NIP-90) and the
//! ranges the README names without listing each number. Names are short slugs
//! chosen here; the number, description and NIP follow the README.
//!
//! The class comes from the number (NIP-01), so the table does not repeat it.

const std = @import("std");

pub const Class = enum {
    regular,
    replaceable,
    ephemeral,
    addressable,

    pub fn label(self: Class) []const u8 {
        return @tagName(self);
    }
};

pub const Info = struct {
    kind: u32,
    name: []const u8,
    description: []const u8,
    /// The defining NIP as the README writes it, such as "01", "C7" or
    /// "65, 51". Empty when the README links no NIP number.
    nip: []const u8,

    pub fn class(self: Info) Class {
        return classOf(self.kind);
    }
};

/// How a relay stores events of this kind (NIP-01).
pub fn classOf(kind: u32) Class {
    if (kind == 0 or kind == 3) return .replaceable;
    if (kind >= 10000 and kind < 20000) return .replaceable;
    if (kind >= 20000 and kind < 30000) return .ephemeral;
    if (kind >= 30000 and kind < 40000) return .addressable;
    return .regular;
}

pub const table = [_]Info{
    .{ .kind = 0, .name = "metadata", .description = "User profile metadata.", .nip = "01" },
    .{ .kind = 1, .name = "text-note", .description = "A short text note.", .nip = "10" },
    .{ .kind = 3, .name = "follows", .description = "The accounts a user follows.", .nip = "02" },
    .{ .kind = 4, .name = "encrypted-direct-message", .description = "Encrypted direct messages.", .nip = "04" },
    .{ .kind = 5, .name = "deletion", .description = "A request to delete earlier events.", .nip = "09" },
    .{ .kind = 6, .name = "repost", .description = "A repost of a text note.", .nip = "18" },
    .{ .kind = 7, .name = "reaction", .description = "A reaction to an event.", .nip = "25" },
    .{ .kind = 8, .name = "badge-award", .description = "The award of a badge to a user.", .nip = "58" },
    .{ .kind = 9, .name = "chat-message", .description = "A chat message.", .nip = "C7" },
    .{ .kind = 11, .name = "thread", .description = "A thread.", .nip = "7D" },
    .{ .kind = 13, .name = "seal", .description = "A sealed rumor inside a gift wrap.", .nip = "59" },
    .{ .kind = 14, .name = "direct-message", .description = "A private direct message rumor.", .nip = "17" },
    .{ .kind = 15, .name = "file-message", .description = "A private file message rumor.", .nip = "17" },
    .{ .kind = 16, .name = "generic-repost", .description = "A repost of any kind of event.", .nip = "18" },
    .{ .kind = 17, .name = "website-reaction", .description = "A reaction to a website.", .nip = "25" },
    .{ .kind = 20, .name = "picture", .description = "A picture post.", .nip = "68" },
    .{ .kind = 21, .name = "video", .description = "A video post.", .nip = "71" },
    .{ .kind = 22, .name = "short-video", .description = "A short vertical video post.", .nip = "71" },
    .{ .kind = 24, .name = "public-message", .description = "A public message.", .nip = "A4" },
    .{ .kind = 30, .name = "internal-reference", .description = "An internal reference to a part of a publication.", .nip = "NKBIP-03" },
    .{ .kind = 31, .name = "external-web-reference", .description = "A reference to an external web resource.", .nip = "NKBIP-03" },
    .{ .kind = 32, .name = "hardcopy-reference", .description = "A reference to a hardcopy publication.", .nip = "NKBIP-03" },
    .{ .kind = 33, .name = "prompt-reference", .description = "A reference to a prompt.", .nip = "NKBIP-03" },
    .{ .kind = 40, .name = "channel-creation", .description = "The creation of a public chat channel.", .nip = "28" },
    .{ .kind = 41, .name = "channel-metadata", .description = "Metadata for a public chat channel.", .nip = "28" },
    .{ .kind = 42, .name = "channel-message", .description = "A message in a public chat channel.", .nip = "28" },
    .{ .kind = 43, .name = "channel-hide-message", .description = "A moderator hides a channel message.", .nip = "28" },
    .{ .kind = 44, .name = "channel-mute-user", .description = "A moderator mutes a user in a channel.", .nip = "28" },
    .{ .kind = 54, .name = "podcast-episode", .description = "A podcast episode.", .nip = "F4" },
    .{ .kind = 62, .name = "request-to-vanish", .description = "A request that relays delete everything from a pubkey.", .nip = "62" },
    .{ .kind = 64, .name = "chess-pgn", .description = "A chess game in PGN format.", .nip = "64" },
    .{ .kind = 78, .name = "application-data", .description = "Application-specific data.", .nip = "78" },
    .{ .kind = 443, .name = "key-package", .description = "A key package for end-to-end encrypted group messaging.", .nip = "Marmot" },
    .{ .kind = 444, .name = "welcome-message", .description = "A welcome message for a group.", .nip = "Marmot" },
    .{ .kind = 445, .name = "group-event", .description = "An event in an end-to-end encrypted group.", .nip = "Marmot" },
    .{ .kind = 818, .name = "merge-request", .description = "A request to merge a wiki article.", .nip = "54" },
    .{ .kind = 1018, .name = "poll-response", .description = "A response to a poll.", .nip = "88" },
    .{ .kind = 1021, .name = "bid", .description = "A bid on an auction.", .nip = "15" },
    .{ .kind = 1022, .name = "bid-confirmation", .description = "A confirmation of an auction bid.", .nip = "15" },
    .{ .kind = 1040, .name = "opentimestamps", .description = "An OpenTimestamps attestation of an event.", .nip = "03" },
    .{ .kind = 1059, .name = "gift-wrap", .description = "A gift wrap around a sealed event.", .nip = "59" },
    .{ .kind = 1063, .name = "file-metadata", .description = "Metadata for a shared file.", .nip = "94" },
    .{ .kind = 1068, .name = "poll", .description = "A poll.", .nip = "88" },
    .{ .kind = 1111, .name = "comment", .description = "A comment on any kind of content.", .nip = "22" },
    .{ .kind = 1222, .name = "voice-message", .description = "A voice message.", .nip = "A0" },
    .{ .kind = 1234, .name = "draft-checkpoint", .description = "A checkpoint of a draft.", .nip = "37" },
    .{ .kind = 1244, .name = "voice-message-comment", .description = "A voice message reply.", .nip = "A0" },
    .{ .kind = 1311, .name = "live-chat-message", .description = "A message in a live stream chat.", .nip = "53" },
    .{ .kind = 1337, .name = "code-snippet", .description = "A code snippet.", .nip = "C0" },
    .{ .kind = 1617, .name = "patch", .description = "A git patch.", .nip = "34" },
    .{ .kind = 1618, .name = "pull-request", .description = "A git pull request.", .nip = "34" },
    .{ .kind = 1619, .name = "pull-request-update", .description = "An update to a git pull request.", .nip = "34" },
    .{ .kind = 1621, .name = "issue", .description = "A git repository issue.", .nip = "34" },
    .{ .kind = 1622, .name = "git-reply", .description = "A reply on a git patch or issue (deprecated).", .nip = "34" },
    .{ .kind = 1630, .name = "status-open", .description = "A git patch or issue status: open.", .nip = "34" },
    .{ .kind = 1631, .name = "status-applied", .description = "A git patch or issue status: applied or merged.", .nip = "34" },
    .{ .kind = 1632, .name = "status-closed", .description = "A git patch or issue status: closed.", .nip = "34" },
    .{ .kind = 1633, .name = "status-draft", .description = "A git patch or issue status: draft.", .nip = "34" },
    .{ .kind = 1971, .name = "problem-tracker", .description = "A problem report.", .nip = "" },
    .{ .kind = 1984, .name = "reporting", .description = "A report of content or a user.", .nip = "56" },
    .{ .kind = 1985, .name = "label", .description = "A label attached to other events.", .nip = "32" },
    .{ .kind = 1987, .name = "vector-embeddings", .description = "Vector lists of embeddings.", .nip = "NKBIP-02" },
    .{ .kind = 2003, .name = "torrent", .description = "A torrent.", .nip = "35" },
    .{ .kind = 2004, .name = "torrent-comment", .description = "A comment on a torrent.", .nip = "35" },
    .{ .kind = 2022, .name = "coinjoin-pool", .description = "A coinjoin pool.", .nip = "" },
    .{ .kind = 4550, .name = "community-post-approval", .description = "A moderator approves a community post.", .nip = "72" },
    .{ .kind = 5128, .name = "nsite-manifest-snapshot", .description = "A snapshot of an nsite manifest.", .nip = "5A" },
    .{ .kind = 7000, .name = "job-feedback", .description = "Feedback on a data vending machine job.", .nip = "90" },
    .{ .kind = 7374, .name = "reserved-cashu-wallet-tokens", .description = "Reserved Cashu wallet tokens.", .nip = "60" },
    .{ .kind = 7375, .name = "cashu-wallet-tokens", .description = "Unspent Cashu wallet tokens.", .nip = "60" },
    .{ .kind = 7376, .name = "cashu-wallet-history", .description = "Cashu wallet spending history.", .nip = "60" },
    .{ .kind = 7516, .name = "geocache-log", .description = "A geocache log.", .nip = "CC" },
    .{ .kind = 7517, .name = "geocache-proof-of-find", .description = "A geocache proof of find.", .nip = "CC" },
    .{ .kind = 8000, .name = "add-user", .description = "A membership event: add a user.", .nip = "43" },
    .{ .kind = 8001, .name = "remove-user", .description = "A membership event: remove a user.", .nip = "43" },
    .{ .kind = 9000, .name = "group-put-user", .description = "A group control event: add a user.", .nip = "29" },
    .{ .kind = 9001, .name = "group-remove-user", .description = "A group control event: remove a user.", .nip = "29" },
    .{ .kind = 9002, .name = "group-edit-metadata", .description = "A group control event: edit group metadata.", .nip = "29" },
    .{ .kind = 9005, .name = "group-delete-event", .description = "A group control event: delete an event.", .nip = "29" },
    .{ .kind = 9007, .name = "group-create-group", .description = "A group control event: create a group.", .nip = "29" },
    .{ .kind = 9008, .name = "group-delete-group", .description = "A group control event: delete a group.", .nip = "29" },
    .{ .kind = 9009, .name = "group-create-invite", .description = "A group control event: create an invite.", .nip = "29" },
    .{ .kind = 9021, .name = "group-join-request", .description = "A request to join a group.", .nip = "29" },
    .{ .kind = 9022, .name = "group-leave-request", .description = "A request to leave a group.", .nip = "29" },
    .{ .kind = 9041, .name = "zap-goal", .description = "A fundraising goal.", .nip = "75" },
    .{ .kind = 9321, .name = "nutzap", .description = "A Cashu token sent as a zap.", .nip = "61" },
    .{ .kind = 9734, .name = "zap-request", .description = "A request to a wallet for a zap invoice.", .nip = "57" },
    .{ .kind = 9735, .name = "zap", .description = "A zap receipt.", .nip = "57" },
    .{ .kind = 9802, .name = "highlight", .description = "A highlight of a passage.", .nip = "84" },
    .{ .kind = 10000, .name = "mute-list", .description = "The list of things a user mutes.", .nip = "51" },
    .{ .kind = 10001, .name = "pin-list", .description = "The notes a user pins.", .nip = "51" },
    .{ .kind = 10002, .name = "relay-list", .description = "The relays a user reads from and writes to.", .nip = "65, 51" },
    .{ .kind = 10003, .name = "bookmark-list", .description = "A user's bookmarks.", .nip = "51" },
    .{ .kind = 10004, .name = "communities-list", .description = "The communities a user belongs to.", .nip = "51" },
    .{ .kind = 10005, .name = "public-chats-list", .description = "The public chats a user is in.", .nip = "51" },
    .{ .kind = 10006, .name = "blocked-relays-list", .description = "The relays a user never connects to.", .nip = "51" },
    .{ .kind = 10007, .name = "search-relays-list", .description = "The relays a user searches on.", .nip = "51" },
    .{ .kind = 10008, .name = "profile-badges-list", .description = "The badges a user displays (legacy list).", .nip = "51, 58" },
    .{ .kind = 10009, .name = "user-groups", .description = "The groups a user is in.", .nip = "51, 29" },
    .{ .kind = 10011, .name = "external-identities", .description = "Identities a user claims on other services.", .nip = "39" },
    .{ .kind = 10012, .name = "favorite-relays-list", .description = "A user's favorite relays.", .nip = "51" },
    .{ .kind = 10013, .name = "private-event-relay-list", .description = "The relays for a user's private events.", .nip = "37" },
    .{ .kind = 10015, .name = "interests-list", .description = "A user's interests.", .nip = "51" },
    .{ .kind = 10019, .name = "nutzap-mint-recommendation", .description = "The mints and keys a user accepts nutzaps on.", .nip = "61" },
    .{ .kind = 10020, .name = "media-follows", .description = "The media a user follows.", .nip = "51" },
    .{ .kind = 10021, .name = "favorite-follow-sets", .description = "A user's favorite follow sets.", .nip = "51" },
    .{ .kind = 10030, .name = "user-emoji-list", .description = "A user's preferred emojis and emoji sets.", .nip = "51" },
    .{ .kind = 10040, .name = "trusted-service-providers", .description = "A user's trusted service providers.", .nip = "85" },
    .{ .kind = 10050, .name = "dm-relays", .description = "The relays for a user's private messages.", .nip = "51, 17" },
    .{ .kind = 10051, .name = "key-package-relays-list", .description = "The relays a user's key packages are published to.", .nip = "Marmot" },
    .{ .kind = 10054, .name = "favorite-podcasts-list", .description = "A user's favorite podcasts.", .nip = "51" },
    .{ .kind = 10063, .name = "user-server-list", .description = "A user's Blossom servers.", .nip = "B7" },
    .{ .kind = 10064, .name = "authored-podcasts-list", .description = "The podcasts a user authored.", .nip = "51" },
    .{ .kind = 10096, .name = "file-storage-server-list", .description = "A user's file storage servers (deprecated).", .nip = "96" },
    .{ .kind = 10133, .name = "payment-targets", .description = "Payment targets.", .nip = "A3" },
    .{ .kind = 10154, .name = "podcast-metadata", .description = "Podcast metadata.", .nip = "F4" },
    .{ .kind = 10166, .name = "relay-monitor-announcement", .description = "A relay monitor announcement.", .nip = "66" },
    .{ .kind = 10312, .name = "room-presence", .description = "Presence in a room.", .nip = "53" },
    .{ .kind = 13194, .name = "wallet-info", .description = "Wallet service info.", .nip = "47" },
    .{ .kind = 13534, .name = "membership-lists", .description = "Membership lists.", .nip = "43" },
    .{ .kind = 15128, .name = "root-nsite-manifest", .description = "The root nsite manifest.", .nip = "5A" },
    .{ .kind = 17375, .name = "cashu-wallet", .description = "A Cashu wallet.", .nip = "60" },
    .{ .kind = 21059, .name = "ephemeral-gift-wrap", .description = "An ephemeral gift wrap.", .nip = "59" },
    .{ .kind = 22242, .name = "client-authentication", .description = "A client authenticates to a relay.", .nip = "42" },
    .{ .kind = 23194, .name = "wallet-request", .description = "A wallet connect request.", .nip = "47" },
    .{ .kind = 23195, .name = "wallet-response", .description = "A wallet connect response.", .nip = "47" },
    .{ .kind = 24133, .name = "nostr-connect", .description = "A remote signing message.", .nip = "46" },
    .{ .kind = 24242, .name = "blossom-auth", .description = "Authorization for a Blossom server.", .nip = "B7" },
    .{ .kind = 27235, .name = "http-auth", .description = "Authorization for an HTTP request.", .nip = "98" },
    .{ .kind = 30000, .name = "follow-sets", .description = "Groups of people a user follows.", .nip = "51" },
    .{ .kind = 30001, .name = "generic-lists", .description = "Generic lists.", .nip = "51" },
    .{ .kind = 30002, .name = "relay-sets", .description = "Sets of relays.", .nip = "51" },
    .{ .kind = 30003, .name = "bookmark-sets", .description = "Sets of bookmarks.", .nip = "51" },
    .{ .kind = 30004, .name = "curation-sets", .description = "Curated sets of articles and notes.", .nip = "51" },
    .{ .kind = 30005, .name = "video-sets", .description = "Curated sets of videos.", .nip = "51" },
    .{ .kind = 30007, .name = "kind-mute-sets", .description = "Mute sets by kind.", .nip = "51" },
    .{ .kind = 30008, .name = "profile-badges", .description = "The badges a user displays.", .nip = "58" },
    .{ .kind = 30009, .name = "badge-definition", .description = "The definition of a badge.", .nip = "58" },
    .{ .kind = 30015, .name = "interest-sets", .description = "Sets of interests.", .nip = "51" },
    .{ .kind = 30017, .name = "stall", .description = "A marketplace stall.", .nip = "15" },
    .{ .kind = 30018, .name = "product", .description = "A marketplace product.", .nip = "15" },
    .{ .kind = 30019, .name = "marketplace-ui", .description = "Marketplace user interface settings.", .nip = "15" },
    .{ .kind = 30020, .name = "product-sold-as-auction", .description = "A product sold as an auction.", .nip = "15" },
    .{ .kind = 30023, .name = "long-form-content", .description = "A long-form article.", .nip = "23" },
    .{ .kind = 30024, .name = "draft-long-form-content", .description = "A draft long-form article.", .nip = "23" },
    .{ .kind = 30030, .name = "emoji-sets", .description = "Sets of custom emojis.", .nip = "51" },
    .{ .kind = 30063, .name = "release-artifact-sets", .description = "Sets of release artifacts.", .nip = "51" },
    .{ .kind = 30078, .name = "application-specific-data", .description = "Data an application stores for a user.", .nip = "78" },
    .{ .kind = 30311, .name = "live-event", .description = "A live event.", .nip = "53" },
    .{ .kind = 30315, .name = "user-status", .description = "A user's status.", .nip = "38" },
    .{ .kind = 30402, .name = "classified-listing", .description = "A classified listing.", .nip = "99" },
    .{ .kind = 30403, .name = "draft-classified-listing", .description = "A draft classified listing.", .nip = "99" },
    .{ .kind = 30617, .name = "repository-announcement", .description = "A git repository announcement.", .nip = "34" },
    .{ .kind = 30618, .name = "repository-state", .description = "The state of a git repository.", .nip = "34" },
    .{ .kind = 30818, .name = "wiki-article", .description = "A wiki article.", .nip = "54" },
    .{ .kind = 30819, .name = "redirect", .description = "A wiki redirect.", .nip = "54" },
    .{ .kind = 31922, .name = "date-calendar-event", .description = "A calendar event on a date.", .nip = "52" },
    .{ .kind = 31923, .name = "time-calendar-event", .description = "A calendar event at a time.", .nip = "52" },
    .{ .kind = 31924, .name = "calendar", .description = "A calendar.", .nip = "52" },
    .{ .kind = 31925, .name = "calendar-event-rsvp", .description = "A response to a calendar event.", .nip = "52" },
    .{ .kind = 31989, .name = "handler-recommendation", .description = "A recommendation of an application for a kind.", .nip = "89" },
    .{ .kind = 31990, .name = "handler-information", .description = "Information about an application that handles a kind.", .nip = "89" },
    .{ .kind = 34235, .name = "video-event", .description = "A horizontal video (legacy).", .nip = "71" },
    .{ .kind = 34236, .name = "short-video-event", .description = "A vertical video (legacy).", .nip = "71" },
    .{ .kind = 34550, .name = "community-definition", .description = "The definition of a community.", .nip = "72" },
    .{ .kind = 39000, .name = "group-metadata", .description = "The metadata of a relay-based group.", .nip = "29" },
    .{ .kind = 39001, .name = "group-admins", .description = "The admins of a relay-based group.", .nip = "29" },
    .{ .kind = 39002, .name = "group-members", .description = "The members of a relay-based group.", .nip = "29" },
    .{ .kind = 39003, .name = "group-roles", .description = "The roles of a relay-based group.", .nip = "29" },
    .{ .kind = 39089, .name = "starter-packs", .description = "A starter pack of people to follow.", .nip = "51" },
    .{ .kind = 39092, .name = "media-starter-packs", .description = "A starter pack of media accounts.", .nip = "51" },
    .{ .kind = 39701, .name = "web-bookmark", .description = "A bookmark of a web page.", .nip = "B0" },
};

/// Kinds that are a whole range sharing a meaning.
const Range = struct { lo: u32, hi: u32, name: []const u8, description: []const u8, nip: []const u8 };

const ranges = [_]Range{
    .{ .lo = 5000, .hi = 5999, .name = "job-request", .description = "A data vending machine job request.", .nip = "90" },
    .{ .lo = 6000, .hi = 6999, .name = "job-result", .description = "A data vending machine job result.", .nip = "90" },
    .{ .lo = 9000, .hi = 9030, .name = "group-control-event", .description = "A group control event.", .nip = "29" },
};

/// The entry for a kind number, if the README names it.
pub fn byNumber(kind: u32) ?Info {
    for (table) |e| if (e.kind == kind) return e;
    for (ranges) |r| {
        if (kind >= r.lo and kind <= r.hi) return .{ .kind = kind, .name = r.name, .description = r.description, .nip = r.nip };
    }
    return null;
}

/// The entry for a name, ignoring case and treating `_` and ` ` as `-`.
pub fn byName(name: []const u8) ?Info {
    var buf: [64]u8 = undefined;
    if (name.len == 0 or name.len > buf.len) return null;
    for (name, 0..) |c, i| buf[i] = switch (c) {
        '_', ' ' => '-',
        else => std.ascii.toLower(c),
    };
    const norm = buf[0..name.len];
    for (table) |e| if (std.mem.eql(u8, e.name, norm)) return e;
    return null;
}

/// A kind given as a number or as a name.
pub fn parse(text: []const u8) ?u32 {
    if (std.fmt.parseInt(u32, text, 10)) |n| return n else |_| {}
    if (byName(text)) |e| return e.kind;
    return null;
}

test "classes follow NIP-01" {
    try std.testing.expectEqual(Class.replaceable, classOf(0));
    try std.testing.expectEqual(Class.replaceable, classOf(3));
    try std.testing.expectEqual(Class.regular, classOf(1));
    try std.testing.expectEqual(Class.replaceable, classOf(10002));
    try std.testing.expectEqual(Class.ephemeral, classOf(22242));
    try std.testing.expectEqual(Class.addressable, classOf(30023));
    try std.testing.expectEqual(Class.regular, classOf(40000));
}

test "names and numbers find each other" {
    try std.testing.expectEqual(@as(?u32, 7), parse("reaction"));
    try std.testing.expectEqual(@as(?u32, 1), parse("Text_Note"));
    try std.testing.expectEqual(@as(?u32, 30023), parse("30023"));
    try std.testing.expectEqual(@as(?u32, null), parse("nonsense"));
    try std.testing.expectEqualStrings("job-request", byNumber(5300).?.name);
}

test "the table is sorted and has no repeated number or name" {
    for (table[1..], 1..) |e, i| {
        try std.testing.expect(e.kind > table[i - 1].kind);
        for (table[0..i]) |p| try std.testing.expect(!std.mem.eql(u8, p.name, e.name));
    }
}
