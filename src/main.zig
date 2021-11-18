const std = @import("std");
const packet_sniffer = @import("packet_sniffer.zig");

pub fn main() anyerror!void {
    var sniffer = packet_sniffer.PacketSniffer{};
    try sniffer.run();
}
