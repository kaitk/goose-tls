// A TLS server for the handshake tests (scripts/test-handshake.sh), one
// connection at a time over blocking sockets of its own (net.c).
//
//   echo_server PORT CERT KEY echo|http
//
// echo sends back every byte it reads, and closes with close_notify after a
// line "bye". http answers each HTTP/1.1 request: a POST with its body, any
// other method with a small JSON object; it closes after a request that asks
// to. For each connection it prints the version, the cipher, and the ALPN
// protocol, or why the handshake failed. ALPN offers h2-less "http/1.1".
import std;
import os;
import tls from "../../";

extern fn net_listen(port: i32, any: bool) -> i64;
extern fn net_accept(fd: i64) -> i64;
extern fn net_recv(fd: i64, buf: u8[:]) -> i64;
extern fn net_send(fd: i64, data: const u8[:]) -> i64;
extern fn net_close(fd: i64);

// Sends everything the connection has waiting.
fn flush(c: tls::Conn, fd: i64, out: u8[:]) {
    loop {
        let n = tls::drain(c, out);
        guard n > 0 else { break; }
        net_send(fd, out[..n]);
    }
}

// The value of a header in head, the request's header lines, or "".
fn header(head: u8[:], name: const u8[:]) -> u8[:] {
    var found = head[..0];
    each_split(head, '\n') {
        let colon = find(it, ":");
        if colon > 0 {
            var key: u8[>..] = [];
            key.append(trim(it[..colon]));
            to_lower(key);
            if key == name { found = trim(it[colon + 1..]); }
        }
    };
    return found;
}

// Answers each whole request in req, and removes it. True once a request
// asked to close.
fn answer(c: tls::Conn, req: u8[>..]&) -> bool {
    var closing = false;
    loop {
        let end = find(req, "\r\n\r\n");
        guard end >= 0 else { break; }
        let head = req[..end];
        let length, ok = parse_int(header(head, "content-length"));
        let body_len = if ok { length } else { 0 };
        guard req.len >= end + 4 + body_len else { break; }
        let body = req[end + 4..end + 4 + body_len];
        var conn: u8[>..] = [];
        conn.append(header(head, "connection"));
        to_lower(conn);
        if conn == "close" { closing = true; }
        let is_post = starts_with(head, "POST ");
        let reply = if is_post { body } else { "{\"message\":\"Hello, World!\"}" };
        let response = str("HTTP/1.1 200 OK\r\nContent-Type: ",
                           if is_post { "application/octet-stream" } else { "application/json" },
                           "\r\nContent-Length: ", reply.len,
                           if closing { "\r\nConnection: close" } else { "" }, "\r\n\r\n", reply);
        tls::write(c, response);
        var rest: u8[>..] = [];
        rest.append(req[end + 4 + body_len..]);
        req.clear();
        req.append(rest);
        if closing { break; }
    }
    return closing;
}

fn serve(ctx: tls::Context, fd: i64, http: bool) {
    let c = tls::accept(ctx);
    guard tls::ok(c) else { print("accept failed: ", tls::error_text()); return; }
    var buf: u8[16384] = [0; 16384];
    var out: u8[16384] = [0; 16384];
    var plain: u8[16384] = [0; 16384];
    var req: u8[>..] = [];
    var shaken = false;
    var done = false;
    while !done {
        let n = net_recv(fd, buf);
        guard n > 0 else { break; }
        tls::feed(c, buf[..n]);
        if !shaken {
            let h = tls::handshake(c);
            if h == tls::FAILED {
                print("handshake failed: ", tls::error_text());
                done = true;
            } else if h == 0 {
                shaken = true;
                let alpn = tls::alpn(c);
                print("handshake: ", tls::version(c), " ", tls::cipher(c), " alpn ",
                      if alpn.len > 0 { alpn } else { "none" });
            }
        }
        while shaken && !done {
            let r = tls::read(c, plain);
            if r == tls::WANT_INPUT { break; }
            if r == tls::CLOSED {
                tls::shutdown(c);
                done = true;
            } else if r == tls::FAILED {
                print("read failed: ", tls::error_text());
                done = true;
            } else if http {
                req.append(plain[..r]);
                if answer(c, req) {
                    tls::shutdown(c);
                    done = true;
                }
            } else {
                tls::write(c, plain[..r]);
                req.append(plain[..r]);
                if ends_with(req, "bye\n") {
                    tls::shutdown(c);
                    done = true;
                }
            }
        }
        flush(c, fd, out);
    }
    flush(c, fd, out);
    tls::free(c);
}

fn main() {
    guard arg_count() == 5 else {
        print("usage: echo_server PORT CERT KEY echo|http");
        exit(2);
    }
    var a: u8[>..] = [];
    arg(1, a);
    let port, pok = parse_int(a);
    var crt: u8[>..] = [];
    arg(2, crt);
    var key: u8[>..] = [];
    arg(3, key);
    var mode: u8[>..] = [];
    arg(4, mode);
    guard pok && (mode == "echo" || mode == "http") else {
        print("usage: echo_server PORT CERT KEY echo|http");
        exit(2);
    }
    let ctx, ok = tls::server_files(crt, key, ["http/1.1"]);
    guard ok else {
        print("no context: ", tls::error_text());
        exit(1);
    }
    let lfd = net_listen(port as i32, false);
    guard lfd >= 0 else {
        print("cannot listen on ", port, ": ", -lfd);
        exit(1);
    }
    print("listening on ", port, " with ", tls::library());
    loop {
        let fd = net_accept(lfd);
        if fd >= 0 {
            serve(ctx, fd, mode == "http");
            net_close(fd);
        }
    }
}
