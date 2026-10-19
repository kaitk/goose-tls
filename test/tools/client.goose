// A TLS client for the handshake tests (scripts/test-handshake.sh), over a
// blocking socket of its own (net.c).
//
//   client HOST PORT [CA_FILE]
//
// It verifies the server against the system's certificate authorities, or
// only against the certificates in CA_FILE, and checks that the certificate
// names HOST. It offers ALPN http/1.1, sends a GET for /, and prints the
// version, the cipher, the ALPN protocol, and the response's status line, or
// why the handshake failed. It exits 0 once it has a status line.
import std;
import os;
import tls from "../../";

extern fn net_connect(host: const u8[:], port: i32) -> i64;
extern fn net_recv(fd: i64, buf: u8[:]) -> i64;
extern fn net_send(fd: i64, data: const u8[:]) -> i64;
extern fn net_close(fd: i64);

// Sends everything the connection has waiting.
fn flush(c: tls::Conn, fd: i64) {
    var out: u8[16384] = [0; 16384];
    loop {
        let n = tls::drain(c, out);
        guard n > 0 else { break; }
        net_send(fd, out[..n]);
    }
}

fn main() {
    guard arg_count() == 3 || arg_count() == 4 else {
        print("usage: client HOST PORT [CA_FILE]");
        exit(2);
    }
    var host: u8[>..] = [];
    arg(1, host);
    var p: u8[>..] = [];
    arg(2, p);
    let port, pok = parse_int(p);
    guard pok else { print("bad port: ", p); exit(2); }
    var ctx = tls::Context { .. };
    var ok = false;
    if arg_count() == 4 {
        var path: u8[>..] = [];
        arg(3, path);
        var ca: u8[>..] = [];
        guard read_file(path, ca) else { print("cannot read ", path); exit(2); }
        ctx, ok = tls::client_trusting(ca, ["http/1.1"]);
    } else {
        ctx, ok = tls::client(["http/1.1"]);
    }
    guard ok else { print("no context: ", tls::error_text()); exit(1); }
    let fd = net_connect(host, port as i32);
    guard fd >= 0 else { print("cannot connect to ", host, ":", port, ": errno ", -fd); exit(1); }
    let c = tls::connect(ctx, host);
    guard tls::ok(c) else { print("connect failed: ", tls::error_text()); exit(1); }

    var buf: u8[16384] = [0; 16384];
    var h = tls::handshake(c);
    flush(c, fd);
    while h == tls::WANT_INPUT {
        let n = net_recv(fd, buf);
        guard n > 0 else { break; }
        tls::feed(c, buf[..n]);
        h = tls::handshake(c);
        flush(c, fd);
    }
    guard h == 0 else {
        print("handshake failed: ", tls::error_text());
        net_close(fd);
        exit(1);
    }
    let alpn = tls::alpn(c);
    print("handshake: ", tls::version(c), " ", tls::cipher(c), " alpn ", if alpn.len > 0 { alpn } else { "none" });

    tls::write(c, str("GET / HTTP/1.1\r\nHost: ", host, "\r\nConnection: close\r\n\r\n"));
    flush(c, fd);
    var response: u8[>..] = [];
    var done = false;
    while !done && find(response, "\r\n") < 0 {
        let n = net_recv(fd, buf);
        guard n > 0 else { break; }
        tls::feed(c, buf[..n]);
        loop {
            let r = tls::read(c, buf);
            if r > 0 { response.append(buf[..r]); continue; }
            if r != tls::WANT_INPUT { done = true; }
            break;
        }
        flush(c, fd);
    }
    let eol = find(response, "\r\n");
    guard eol >= 0 else {
        print("no response: ", tls::error_text());
        net_close(fd);
        exit(1);
    }
    print("response: ", response[..eol]);
    tls::shutdown(c);
    flush(c, fd);
    tls::free(c);
    tls::free(ctx);
    net_close(fd);
}
