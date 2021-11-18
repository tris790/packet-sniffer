// Inspired by: https://gist.github.com/Accalmie/d328287c05f0a417892f
// Simple Sniffer in winsock by Silver Moon ( m00n.silv3r@gmail.com )

const std = @import("std");
const ws = @cImport(@cInclude("winsock2.h"));

const Protocol = enum(u8) { TCP = 6, UDP = 17 };

// Bit field order reversed because data is received as Big Endian but we are running on
// Little Endian hardware
const IPV4HeaderBE = packed struct {
    _header_len: u4,
    version: u4,
    tos: u8,
    _total_len: u16,
    _identification: u16,
    fragment_offset: u5,
    flags: u3,
    fragment_offset_1: u8,
    ttl: u8,
    protocol: u8,
    _hdr_checksum: u16,
    _src_addr: u32,
    _dest_addr: u32,

    pub fn header_len_byte_size(self: *IPV4HeaderBE) u8 {
        return @intCast(u8, self._header_len) * 4;
    }

    pub fn total_len(self: *IPV4HeaderBE) u16 {
        return ws.ntohs(self._total_len);
    }

    pub fn identification(self: *IPV4HeaderBE) u16 {
        return ws.ntohs(self._identification);
    }

    pub fn hdr_checksum(self: *IPV4HeaderBE) u16 {
        return ws.ntohs(self._hdr_checksum);
    }
    pub fn src_addr(self: *IPV4HeaderBE) [*c]u8 {
        var source = std.mem.zeroInit(ws.sockaddr_in, .{});
        source.sin_addr.S_un.S_addr = self._src_addr;
        return ws.inet_ntoa(source.sin_addr);
    }
    pub fn dest_addr(self: *IPV4HeaderBE) [*c]u8 {
        var dest = std.mem.zeroInit(ws.sockaddr_in, .{});
        dest.sin_addr.S_un.S_addr = self._dest_addr;
        return ws.inet_ntoa(dest.sin_addr);
    }
};

const UDPHeaderBE = packed struct {
    _source_port: u16,
    _dest_port: u16,
    _udp_length: u16,
    _udp_checksum: u16,

    pub fn source_port(self: *UDPHeaderBE) u16 {
        return ws.ntohs(self._source_port);
    }

    pub fn dest_port(self: *UDPHeaderBE) u16 {
        return ws.ntohs(self._dest_port);
    }

    pub fn udp_length(self: *UDPHeaderBE) u16 {
        return ws.ntohs(self._udp_length);
    }

    pub fn udp_checksum(self: *UDPHeaderBE) u16 {
        return ws.ntohs(self._udp_checksum);
    }
};

// Bit field order reversed because data is received as Big Endian but we are running on
// Little Endian hardware
const TCPHeaderBE = packed struct {
    _source_port: u16,
    _dest_port: u16,
    _sequence_num: u32,
    _acknowledge: u32,
    reserved: u4,
    _header_len: u4,
    fin: u1,
    syn: u1,
    rst: u1,
    psh: u1,
    ack: u1,
    urg: u1,
    ecn: u1,
    cwr: u1,
    _window_size: u16,
    _checksum: u16,
    urgent_pointer: u16,

    pub fn source_port(self: *TCPHeaderBE) u16 {
        return ws.ntohs(self._source_port);
    }

    pub fn dest_port(self: *TCPHeaderBE) u16 {
        return ws.ntohs(self._dest_port);
    }

    pub fn sequence_num(self: *TCPHeaderBE) u32 {
        return ws.ntohl(self._sequence_num);
    }

    pub fn acknowledge(self: *TCPHeaderBE) u32 {
        return ws.ntohl(self._acknowledge);
    }

    pub fn header_len_byte_size(self: *TCPHeaderBE) u8 {
        return @intCast(u8, self._header_len) * 4;
    }

    pub fn window_size(self: *TCPHeaderBE) u32 {
        return ws.ntohs(self._window_size);
    }

    pub fn checksum(self: *TCPHeaderBE) u32 {
        return ws.ntohs(self._checksum);
    }
};

comptime {
    if (@sizeOf(IPV4HeaderBE) != 20) {
        @compileError("IPV4HeaderBE should be 20 bytes");
    }
    if (@sizeOf(TCPHeaderBE) != 20) {
        @compileError("TCPHeaderBE should be 20 bytes");
    }
    if (@sizeOf(UDPHeaderBE) != 8) {
        @compileError("UDPHeaderBE should be 4 bytes");
    }
}

const PacketSnifferError = error{
    WSASTARTUP_FAILED,
    INVALID_SOCKET,
    INVALID_HOSTNAME,
    INVALID_NETWORK_INTERFACE,
    BIND_FAILED,
    WSAIOCTL_FAILED,
};

pub const PacketSniffer = struct {
    sniffing_socket: ws.SOCKET = undefined,

    const Self = @This();
    pub fn run(self: *Self) PacketSnifferError!void {
        // Initialize WSA
        if (ws.WSAStartup(ws.MAKEWORD(2, 2), &std.mem.zeroInit(ws.WSADATA, .{})) != 0) {
            std.debug.print("Failed to create raw socket\n", .{});
            return error.WSASTARTUP_FAILED;
        }

        // Create a raw socket (Requires administrator permission)
        self.sniffing_socket = ws.socket(ws.AF_INET, ws.SOCK_RAW, ws.IPPROTO_IP);
        if (self.sniffing_socket == ws.INVALID_SOCKET) {
            std.debug.print("Failed to create raw socket, make sure this is running as administrator\n", .{});
            return error.INVALID_SOCKET;
        }

        // Get hostname
        var hostname: [100]u8 = undefined;
        if (ws.gethostname(@ptrCast([*c]u8, &hostname), @sizeOf(u8) * hostname.len) == ws.SOCKET_ERROR) {
            return error.INVALID_HOSTNAME;
        }

        // Get network interfaces
        var local: *ws.hostent = ws.gethostbyname(@ptrCast([*c]u8, &hostname));

        var dest = std.mem.zeroInit(ws.sockaddr_in, .{});
        dest.sin_family = ws.AF_INET;
        dest.sin_port = 0;

        std.debug.print("Choose a network interface: \n", .{});

        // Display the network interface
        var network_interface_index: u8 = 0;
        while (local.h_addr_list[network_interface_index]) |network_interface| {
            var tmp_addr = std.mem.zeroInit(ws.sockaddr_in, .{});
            @memcpy(@ptrCast([*]u8, &tmp_addr.sin_addr.S_un.S_addr), @ptrCast([*]const u8, network_interface), @sizeOf(u64));

            std.debug.print("[{}] {s}\n", .{ network_interface_index, ws.inet_ntoa(tmp_addr.sin_addr) });
            network_interface_index += 1;
        }

        // Choose the desired network interface
        const stdin = std.io.getStdIn().reader();
        // FIXME: only supports up to 9 interfaces
        const ascii_input = try stdin.readByte() catch error.INVALID_NETWORK_INTERFACE;
        var captured_network_interface: u32 = ascii_input - '0';
        var captured_ip = local.h_addr_list[captured_network_interface];

        @memcpy(@ptrCast([*]u8, &dest.sin_addr.S_un.S_addr), @ptrCast([*]const u8, captured_ip), @sizeOf(u64));

        // Bind the sniffer on the desired port
        if (ws.bind(self.sniffing_socket, @ptrCast([*c]const ws.sockaddr, &dest), @sizeOf(ws.sockaddr_in)) == ws.SOCKET_ERROR) {
            std.debug.print("Socket binding failed\n", .{});
            return error.BIND_FAILED;
        }
        var j: u32 = 1;
        const wasiotcl_result = ws.WSAIoctl(
            self.sniffing_socket,
            ws._WSAIOW(@intCast(u32, ws.IOC_VENDOR), @as(u32, 1)),
            &j,
            @sizeOf(u32),
            null,
            @as(u32, 0),
            &captured_network_interface,
            0,
            null,
        );
        if (wasiotcl_result == ws.SOCKET_ERROR) {
            std.debug.print("WSAIOCTL_FAILED failed\n", .{});
            return error.WSAIOCTL_FAILED;
        }

        try self.sniff();
    }

    fn sniff(self: *Self) PacketSnifferError!void {
        std.debug.print("Stared sniffing\n", .{});
        var tmp_buf: [std.math.maxInt(u16)]u8 = undefined;

        while (true) {
            const recv_result = ws.recvfrom(self.sniffing_socket, &tmp_buf, std.math.maxInt(u16), 0, 0, 0);
            if (recv_result == ws.SOCKET_ERROR) {
                std.debug.print("RECV Error = {}\n", .{ws.WSAGetLastError()});
            }

            const len = @intCast(usize, recv_result);
            std.debug.print("[RAW] {}\n", .{std.fmt.fmtSliceHexLower(tmp_buf[0..len])});

            var buf_slice = tmp_buf[0..len];
            try process_ipv4_packet(buf_slice);
            std.debug.print("\n", .{});
        }
    }

    fn process_ipv4_packet(buffer: []u8) PacketSnifferError!void {
        var ipv4_header: *IPV4HeaderBE = @ptrCast(*IPV4HeaderBE, buffer);
        std.debug.print("[IPV4] {s}\n", .{ipv4_header});

        switch (ipv4_header.protocol) {
            @enumToInt(Protocol.TCP) => try process_tcp_packet(buffer),
            @enumToInt(Protocol.UDP) => try process_udp_packet(buffer),
            else => std.debug.print("Unsupported packet type: {}\n", .{ipv4_header.protocol}),
        }
    }

    fn process_tcp_packet(buffer: []u8) PacketSnifferError!void {
        var ipv4_header: *IPV4HeaderBE = @ptrCast(*IPV4HeaderBE, buffer);
        var tcp_header: *TCPHeaderBE = @ptrCast(*TCPHeaderBE, buffer[ipv4_header.header_len_byte_size()..]);
        std.debug.print("[TCP] {s}\n", .{tcp_header});

        std.debug.print("{s} -> {s} [{} -> {}] {} bytes\n", .{ ipv4_header.src_addr(), ipv4_header.dest_addr(), tcp_header.source_port(), tcp_header.dest_port(), buffer.len });
    }

    fn process_udp_packet(buffer: []u8) PacketSnifferError!void {
        var ipv4_header: *IPV4HeaderBE = @ptrCast(*IPV4HeaderBE, buffer);
        var udp_header: *UDPHeaderBE = @ptrCast(*UDPHeaderBE, buffer[ipv4_header.header_len_byte_size()..]);

        std.debug.print("[UDP] {s}\n", .{udp_header});

        std.debug.print("{s} -> {s} [{} -> {}] {} bytes\n", .{ ipv4_header.src_addr(), ipv4_header.dest_addr(), udp_header.source_port(), udp_header.dest_port(), buffer.len });
    }
};
