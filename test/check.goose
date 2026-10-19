// What the tests under test/ share. Each check prints what it checked, for the
// test's golden file in test/expected/, then asserts it, so a failure shows
// in the output as well as in the exit code. A client and a server talk
// through the program's memory, with no sockets.
namespace check;

import std;
import tls from "../";

// Prints "label: ok", or "label: FAILED".
fn that(label: const u8[:], ok: bool) {
    print(label, if ok { ": ok" } else { ": FAILED" });
    assert(ok);
}

// Prints the value, and what was expected if it differs.
fn eq(label: const u8[:], got: i64, want: i64) {
    if got == want { print(label, ": ", got); }
    else { print(label, ": ", got, ", expected ", want, ": FAILED"); }
    assert(got == want);
}

fn status(n: i64) -> const u8[:] {
    match n {
        tls::WANT_INPUT => "WANT_INPUT",
        tls::CLOSED => "CLOSED",
        tls::FAILED => "FAILED",
        tls::HELLO => "HELLO",
        0 => "done",
        _ => if n > 0 { "a count" } else { "another status" },
    }
}

// Moves every byte waiting in from into to, and returns how many.
fn pass(from: tls::Conn, to: tls::Conn) -> i64 {
    var buf: u8[4096] = [0; 4096];
    var moved = 0;
    loop {
        let n = tls::drain(from, buf);
        guard n > 0 else { break; }
        tls::feed(to, buf[..n]);
        moved += n;
    }
    return moved;
}

// Runs the handshake between a client and a server until both are done, one
// fails, or the server pauses at HELLO, and returns the server's status then
// (0 when both are done), with the client's in client_status.
fn handshake(client: tls::Conn, server: tls::Conn, client_status: i64&) -> i64 {
    var cs = tls::handshake(client);
    var ss = tls::WANT_INPUT;
    for round in 10 {
        pass(client, server);
        if ss != 0 { ss = tls::handshake(server); }
        guard ss != tls::HELLO && ss != tls::FAILED else { break; }
        pass(server, client);
        if cs != 0 { cs = tls::handshake(client); }
        guard cs != tls::FAILED else { break; }
        guard cs != 0 || ss != 0 else { break; }
    }
    // A failed client's alert, for the server to read.
    pass(client, server);
    client_status = cs;
    return ss;
}

// Sends text from one end to the other, and returns what arrived.
fn send(from: tls::Conn, to: tls::Conn, text: const u8[:]) -> u8[>..] {
    var got: u8[>..] = [];
    guard tls::write(from, text) == text.len else { return got; }
    pass(from, to);
    var buf: u8[4096] = [0; 4096];
    loop {
        let n = tls::read(to, buf);
        guard n > 0 else { break; }
        got.append(buf[..n]);
    }
    return got;
}

// The last line of error_text, with OpenSSL's code, library, and function cut
// off: its reason and the text added to it, which OpenSSL 3.0 to 4.x give
// alike.
fn reason() -> u8[>..] {
    let e = tls::error_text();
    var line = trim(e);
    let nl = rfind(line, "\n");
    if nl >= 0 { line = line[nl + 1..]; }
    // "error:0A000086:SSL routines:<function, before 3.2>:certificate verify failed:why"
    var colons = 0;
    var start = 0;
    for b, i in line {
        if b == ':' {
            colons += 1;
            if colons == 4 { start = i + 1; }
        }
    }
    var out: u8[>..] = [];
    out.append(line[start..]);
    return out;
}
