// A key or certificate call outside tls::run, which it leaves through when it
// fails, doesn't compile.
import tls from "../../";

fn main() {
    let k = tls::key_generate(tls::P256);
    tls::free(k);
}
// error: return from run: no enclosing call of run on this compile-time call path
