// A TLS server for the handshake tests (scripts/test-handshake.sh), one
// connection at a time over blocking sockets of its own (net.c).
//
//   echo_server PORT CERT KEY echo|http [kernel|choose]
//
// echo sends back every byte it reads, and closes with close_notify after a
// line "bye". http answers each HTTP/1.1 request: a POST with its body, any
// other method with a small JSON object; it closes after a request that asks
// to. For each connection it prints the version, the cipher, and the ALPN
// protocol, or why the handshake failed. ALPN offers h2-less "http/1.1".
//
// With kernel, it moves each connection to kTLS after the handshake where the
// kernel has it, and prints which directions the kernel took and each record
// that isn't data; elsewhere it serves from user space, as without.
//
// With choose, it picks each connection's context at the ClientHello, as an
// ACME client's TLS-ALPN-01 does: a client that sends acme.test in SNI and
// offers acme-tls/1 gets a challenge certificate for acme.test, whose
// acmeIdentifier is check::DIGEST, the SHA-256 of "token.thumbprint", and ALPN
// acme-tls/1; one that sends other.test gets a self-signed certificate for
// other.test; every other gets CERT. It prints each choice.
import std;
import os;
import tls from "../../";
import check from "../";

// The contexts choose picks from.
var other = tls::Context { .. };
var acme = tls::Context { .. };

extern fn net_listen(port: i32, any: bool) -> i64;
extern fn net_accept(fd: i64) -> i64;
extern fn net_recv(fd: i64, buf: u8[:]) -> i64;
extern fn net_send(fd: i64, data: const u8[:]) -> i64;
extern fn net_close(fd: i64);
extern fn net_recv_record(fd: i64, buf: u8[:]) -> i64;
extern fn net_record_type() -> i64;
extern fn net_send_record(fd: i64, kind: i64, data: const u8[:]) -> i64;
// The shim's, for tests: kTLS enabled on a context where the kernel has none.
extern "tls_kernel_enable" fn kernel_enable(ctx: i64, anywhere: bool) -> bool;

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

// Answers each whole request in req into reply, and removes it. True once a
// request asked to close.
fn answer(req: u8[>..]&, reply: u8[>..]&) -> bool {
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
        let content = if is_post { body } else { "{\"message\":\"Hello, World!\"}" };
        format(reply, "HTTP/1.1 200 OK\r\nContent-Type: ",
               if is_post { "application/octet-stream" } else { "application/json" },
               "\r\nContent-Length: ", content.len,
               if closing { "\r\nConnection: close" } else { "" }, "\r\n\r\n", content);
        var rest: u8[>..] = [];
        rest.append(req[end + 4 + body_len..]);
        req.clear();
        req.append(rest);
        if closing { break; }
    }
    return closing;
}

// Takes plaintext the client sent, and puts what to send back in reply. True
// once the connection is to close.
fn respond(http: bool, plain: const u8[:], req: u8[>..]&, reply: u8[>..]&) -> bool {
    req.append(plain);
    guard !http else { return answer(req, reply); }
    reply.append(plain);
    return ends_with(req, "bye\n");
}

fn kernel_name(dirs: i64) -> const u8[:] {
    match dirs {
        3 => "RX TX",
        1 => "RX",
        _ => "none",
    }
}

fn record_status(r: i64) -> const u8[:] {
    match r {
        0 => "0",
        tls::UPDATE_TX => "UPDATE_TX",
        tls::CLOSED => "CLOSED",
        _ => "FAILED",
    }
}

// Serves the rest of a connection whose receiving the kernel holds, and
// whose sending it holds too when tx is set.
fn serve_kernel(c: tls::Conn, fd: i64, http: bool, tx: bool, req: u8[>..]&) {
    var buf: u8[16384] = [0; 16384];
    var out: u8[16384] = [0; 16384];
    var done = false;
    while !done {
        let n = net_recv_record(fd, buf);
        guard n > 0 else {
            if n < 0 { print("kernel recv failed: errno ", -n); }
            break;
        }
        let kind = net_record_type();
        var closing = false;
        if kind == 23 {
            var reply: u8[>..] = [];
            closing = respond(http, buf[..n], req, reply);
            if tx { net_send(fd, reply); } else { tls::write(c, reply); }
        } else {
            let r = tls::kernel_record(c, fd, kind, buf[..n]);
            print("kernel record: type ", kind, ", ", record_status(r));
            if r == tls::UPDATE_TX {
                net_send_record(fd, tls::RECORD_HANDSHAKE, tls::KEY_UPDATE);
                if tls::kernel_update_tx(c, fd) != 0 {
                    print("kernel_update_tx failed: ", tls::error_text());
                    done = true;
                }
            } else if r == tls::CLOSED {
                closing = true;
            } else if r == tls::FAILED {
                print("kernel_record failed: ", tls::error_text());
                done = true;
            }
        }
        if closing {
            if tx { net_send_record(fd, tls::RECORD_ALERT, tls::CLOSE_NOTIFY); } else { tls::shutdown(c); }
            done = true;
        }
        if !tx { flush(c, fd, out); }
    }
}

// Moves a connection paused at its ClientHello to the context its SNI name
// and ALPN offer pick.
fn choose(c: tls::Conn) {
    let name = tls::server_name(c);
    let acme_tls = tls::offers(c, "acme-tls/1");
    var picked = "default";
    if name == "acme.test" && acme_tls {
        picked = "acme";
        tls::use_context(c, acme);
    } else if name == "other.test" {
        picked = "other";
        tls::use_context(c, other);
    }
    print("hello: server_name '", name, "', acme-tls/1 ", acme_tls, ", context ", picked);
}

fn serve(ctx: tls::Context, fd: i64, http: bool, kernel: bool) {
    let c = tls::accept(ctx);
    guard tls::ok(c) else { print("accept failed: ", tls::error_text()); return; }
    var buf: u8[16384] = [0; 16384];
    var out: u8[16384] = [0; 16384];
    var plain: u8[16384] = [0; 16384];
    var req: u8[>..] = [];
    var shaken = false;
    var done = false;
    var asked = false;
    // At most what completes a record, while the switch to the kernel waits
    // for one to end.
    var want = buf.len;
    while !done {
        let n = net_recv(fd, buf[..want]);
        guard n > 0 else { break; }
        want = buf.len;
        tls::feed(c, buf[..n]);
        if !shaken {
            var h = tls::handshake(c);
            if h == tls::HELLO {
                choose(c);
                h = tls::handshake(c);
            }
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
            } else {
                var reply: u8[>..] = [];
                done = respond(http, plain[..r], req, reply);
                tls::write(c, reply);
                if done { tls::shutdown(c); }
            }
        }
        flush(c, fd, out);
        if kernel && shaken && !done && !asked {
            let k = tls::to_kernel(c, fd);
            if k == tls::WANT_INPUT {
                want = tls::kernel_wants(c);
            } else if k >= 0 {
                asked = true;
                let why: u8[>..] = if k == 0 { str(" (", tls::error_text(), ")") } else { "" };
                print("kernel: ", kernel_name(k), why);
                if (k & tls::KERNEL_RX) != 0 {
                    serve_kernel(c, fd, http, (k & tls::KERNEL_TX) != 0, req);
                    done = true;
                }
            }
        }
    }
    flush(c, fd, out);
    tls::free(c);
}

fn main() {
    let usage = "usage: echo_server PORT CERT KEY echo|http [kernel|choose]";
    guard arg_count() == 5 || arg_count() == 6 else {
        print(usage);
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
    var opt: u8[>..] = [];
    if arg_count() == 6 { arg(5, opt); }
    guard pok && (mode == "echo" || mode == "http") && (opt == "" || opt == "kernel" || opt == "choose") else {
        print(usage);
        exit(2);
    }
    let kernel = opt == "kernel";
    let ctx, ok = tls::server_files(crt, key, ["http/1.1"]);
    guard ok else {
        print("no context: ", tls::error_text());
        exit(1);
    }
    if kernel {
        let yes = tls::use_kernel(ctx);
        print("kernel tls: ", if yes { "yes" } else { "no" });
        // Where the kernel has none, connections still try, to check that
        // to_kernel leaves them in user space.
        if !yes { kernel_enable(ctx.id, true); }
    }
    if opt == "choose" {
        var pem: u8[>..] = [];
        var other_crt: u8[>..] = [];
        var acme_crt: u8[>..] = [];
        let failed = tls::run() {
            let k = tls::key_generate(tls::P256);
            pem = tls::key_pem(k);
            other_crt = tls::self_signed(k, ["other.test"], 1);
            acme_crt = tls::challenge_certificate(k, "acme.test", check::DIGEST);
            tls::free(k);
        };
        for e in failed {
            print("no certificates: ", e.message);
            exit(1);
        }
        var ook = false;
        var aok = false;
        other, ook = tls::server(other_crt, pem, ["http/1.1"]);
        acme, aok = tls::server(acme_crt, pem, ["acme-tls/1"]);
        guard ook && aok && tls::choose_context(ctx) else {
            print("no contexts to choose from: ", tls::error_text());
            exit(1);
        }
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
            serve(ctx, fd, mode == "http", kernel);
            net_close(fd);
        }
    }
}
