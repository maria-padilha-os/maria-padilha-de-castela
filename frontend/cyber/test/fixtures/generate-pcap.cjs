"use strict";

/*
 * Test-only generator for a small, deterministic pcap fixture.
 *
 * The fixture contains one Ethernet/IPv4/TCP packet with an HTTP request that
 * deliberately includes an Authorization header, a Cookie, a session token,
 * and a password in the body. Tests use it to prove that the forensics summary
 * redacts sensitive fields. No live capture, interface, or tshark process is
 * involved in generating it.
 *
 * Usage:
 *   node test/fixtures/generate-pcap.cjs [output.pcap]
 */

const fs = require("node:fs");
const path = require("node:path");

function checksum(buffer) {
    let sum = 0;
    for (let index = 0; index < buffer.length; index += 2) {
        const word = (buffer[index] << 8) +
            (index + 1 < buffer.length ? buffer[index + 1] : 0);
        sum += word;
        while (sum > 0xffff) {
            sum = (sum & 0xffff) + (sum >>> 16);
        }
    }
    return (~sum) & 0xffff;
}

const HTTP_PAYLOAD = Buffer.from(
    "GET /login?token=fixture-token-value HTTP/1.1\r\n" +
    "Host: lab-vm.example\r\n" +
    "User-Agent: maria-padilha-fixture/1.0\r\n" +
    "Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n" +
    "Cookie: session=fixture-session-value\r\n" +
    "\r\n" +
    "password=hunter2&api_key=fixture-api-key\r\n",
    "utf8"
);

function buildSamplePcap() {
    const ethernet = Buffer.alloc(14);
    Buffer.from("020000000002", "hex").copy(ethernet, 0);
    Buffer.from("020000000001", "hex").copy(ethernet, 6);
    ethernet.writeUInt16BE(0x0800, 12);

    const tcp = Buffer.alloc(20);
    tcp.writeUInt16BE(49152, 0);
    tcp.writeUInt16BE(80, 2);
    tcp.writeUInt32BE(1, 4);
    tcp.writeUInt32BE(1, 8);
    tcp.writeUInt8(5 << 4, 12);
    tcp.writeUInt8(0x18, 13);
    tcp.writeUInt16BE(64240, 14);
    tcp.writeUInt16BE(0, 16);
    tcp.writeUInt16BE(0, 18);

    const source = Buffer.from([192, 0, 2, 10]);
    const destination = Buffer.from([192, 0, 2, 20]);
    const ip = Buffer.alloc(20);
    ip.writeUInt8(0x45, 0);
    ip.writeUInt8(0, 1);
    ip.writeUInt16BE(20 + tcp.length + HTTP_PAYLOAD.length, 2);
    ip.writeUInt16BE(0x1234, 4);
    ip.writeUInt16BE(0x4000, 6);
    ip.writeUInt8(64, 8);
    ip.writeUInt8(6, 9);
    ip.writeUInt16BE(0, 10);
    source.copy(ip, 12);
    destination.copy(ip, 16);
    ip.writeUInt16BE(checksum(ip), 10);

    const pseudo = Buffer.alloc(12);
    source.copy(pseudo, 0);
    destination.copy(pseudo, 4);
    pseudo.writeUInt8(0, 8);
    pseudo.writeUInt8(6, 9);
    pseudo.writeUInt16BE(tcp.length + HTTP_PAYLOAD.length, 10);
    tcp.writeUInt16BE(checksum(Buffer.concat([pseudo, tcp, HTTP_PAYLOAD])), 16);

    const packet = Buffer.concat([ethernet, ip, tcp, HTTP_PAYLOAD]);

    const globalHeader = Buffer.alloc(24);
    globalHeader.writeUInt32LE(0xa1b2c3d4, 0);
    globalHeader.writeUInt16LE(2, 4);
    globalHeader.writeUInt16LE(4, 6);
    globalHeader.writeInt32LE(0, 8);
    globalHeader.writeUInt32LE(0, 12);
    globalHeader.writeUInt32LE(262144, 16);
    globalHeader.writeUInt32LE(1, 20);

    const recordHeader = Buffer.alloc(16);
    recordHeader.writeUInt32LE(1767225600, 0);
    recordHeader.writeUInt32LE(123456, 4);
    recordHeader.writeUInt32LE(packet.length, 8);
    recordHeader.writeUInt32LE(packet.length, 12);

    return Buffer.concat([globalHeader, recordHeader, packet]);
}

function writeSamplePcap(filePath) {
    const target = filePath || path.join(__dirname, "lab-capture.pcap");
    fs.writeFileSync(target, buildSamplePcap());
    return target;
}

if (require.main === module) {
    const target = process.argv[2] || path.join(__dirname, "lab-capture.pcap");
    process.stdout.write(writeSamplePcap(target) + "\n");
}

module.exports = {
    buildSamplePcap,
    writeSamplePcap,
    HTTP_PAYLOAD
};
