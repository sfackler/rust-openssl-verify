//! Hostname verification for OpenSSL.
//!
//! OpenSSL up until version 1.1.0 did not verify that the certificate a server
//! presents matches the domain a client is connecting to. This check is
//! crucial, as an attacker otherwise needs only to obtain a legitimately
//! signed certificate to *some* domain to execute a man-in-the-middle attack.
//!
//! The implementation in this crate is based off of libcurl's.
//!
//! # Examples
//!
//! In most cases, the `verify_callback` function should be used in OpenSSL's
//! verification callback:
//!
/// ```
/// extern crate openssl;
/// extern crate openssl_verify;
///
/// use std::net::TcpStream;
/// use openssl::ssl::{SslContext, SslMethod, SslStream, SSL_VERIFY_PEER, IntoSsl};
/// use openssl_verify::verify_callback;
///
/// # fn main() {
/// let domain = "google.com";
/// let stream = TcpStream::connect((domain, 443)).unwrap();
///
/// let mut ctx = SslContext::new(SslMethod::Sslv23).unwrap();
/// ctx.set_default_verify_paths().unwrap();
///
/// let mut ssl = ctx.into_ssl().unwrap();
/// let domain = domain.to_owned();
/// ssl.set_verify(SSL_VERIFY_PEER, move |p, x| verify_callback(&domain, p, x));
///
/// let ssl_stream = SslStream::connect(ssl, stream).unwrap();
/// # }

extern crate openssl;

use openssl::nid::Nid;
use openssl::x509::{X509StoreContext, X509, GeneralNames, X509Name};
use std::net::IpAddr;

/// A convenience wrapper around verify_hostname that implements the logic for
/// OpenSSL's certificate verification callback.
///
/// If `preverify_ok` is false or the certificate depth is not 0, it will
/// simply return the value of `preverify_ok`. It will otherwise validate the
/// that the provided fully qualified domain name matches that of the leaf
/// certificate.
pub fn verify_callback(domain: &str, preverify_ok: bool, x509_ctx: &X509StoreContext) -> bool {
    if !preverify_ok || x509_ctx.error_depth() != 0 {
        return preverify_ok;
    }

    match x509_ctx.get_current_cert() {
        Some(x509) => verify_hostname(domain, &x509),
        None => true,
    }
}

/// Validates that the certificate matches the provided fully qualified domain
/// name.
pub fn verify_hostname(domain: &str, cert: &X509) -> bool {
    match cert.subject_alt_names() {
        Some(names) => verify_subject_alt_names(domain, &names),
        None => verify_subject_name(domain, &cert.subject_name()),
    }
}

fn verify_subject_alt_names(domain: &str, names: &GeneralNames) -> bool {
    let ip = domain.parse();

    for i in 0..names.len() {
        let name = names.get(i);
        match ip {
            Ok(ip) => {
                if let Some(actual) = name.ipadd() {
                    if matches_ip(&ip, actual) {
                        return true;
                    }
                }
            }
            Err(_) => {
                if let Some(pattern) = name.dns() {
                    if matches_dns(pattern, domain, false) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

fn verify_subject_name(domain: &str, subject_name: &X509Name) -> bool {
    if let Some(pattern) = subject_name.text_by_nid(Nid::CN) {
        // Unlike with SANs, IP addresses in the subject name don't have a
        // different encoding. We need to pass this down to matches_dns to
        // disallow wildcard matches with bogus patterns like *.0.0.1
        let is_ip = domain.parse::<IpAddr>().is_ok();

        if matches_dns(&pattern, domain, is_ip) {
            return true;
        }
    }

    false
}

fn matches_dns(mut pattern: &str, mut hostname: &str, is_ip: bool) -> bool {
    // first strip trailing . off of pattern and hostname to normalize
    if pattern.ends_with('.') {
        pattern = &pattern[..pattern.len() - 1];
    }
    if hostname.ends_with('.') {
        hostname = &hostname[..hostname.len() - 1];
    }

    matches_wildcard(pattern, hostname, is_ip).unwrap_or_else(|| pattern == hostname)
}

fn matches_wildcard(pattern: &str, hostname: &str, is_ip: bool) -> Option<bool> {
    // IP addresses and internationalized domains can't involved in wildcards
    if is_ip || pattern.starts_with("xn--") {
        return None;
    }

    let wildcard_location = match pattern.find('*') {
        Some(l) => l,
        None => return None,
    };

    let mut dot_idxs = pattern.match_indices('.').map(|(l, _)| l);
    let wildcard_end = match dot_idxs.next() {
        Some(l) => l,
        None => return None,
    };

    // Never match wildcards if the pattern has less than 2 '.'s (no *.com)
    //
    // This is a bit dubious, as it doesn't disallow other TLDs like *.co.uk.
    // Chrome has a black- and white-list for this, but Firefox (via NSS) does
    // the same thing we do here.
    //
    // The Public Suffix (https://www.publicsuffix.org/) list could
    // potentically be used here, but it's both huge and updated frequently
    // enough that management would be a PITA.
    if dot_idxs.next().is_none() {
        return None;
    }

    // Wildcards can only be in the first component
    if wildcard_location > wildcard_end {
        return None;
    }

    let hostname_label_end = match hostname.find('.') {
        Some(l) => l,
        None => return None,
    };

    // check that the non-wildcard parts are identical
    if pattern[wildcard_end..] != hostname[hostname_label_end..] {
        return Some(false);
    }

    let wildcard_prefix = &pattern[..wildcard_location];
    let wildcard_suffix = &pattern[wildcard_location + 1..wildcard_end];

    let hostname_label = &hostname[..hostname_label_end];

    // check the prefix of the first label
    if !hostname_label.starts_with(wildcard_prefix) {
        return Some(false);
    }

    // and the suffix
    if !hostname_label[wildcard_prefix.len()..].ends_with(wildcard_suffix) {
        return Some(false);
    }

    Some(true)
}

fn matches_ip(expected: &IpAddr, actual: &[u8]) -> bool {
    match (expected, actual.len()) {
        (&IpAddr::V4(ref addr), 4) => actual == addr.octets(),
        (&IpAddr::V6(ref addr), 16) => {
            let segments = [((actual[0] as u16) << 8) | actual[1] as u16,
                            ((actual[2] as u16) << 8) | actual[3] as u16,
                            ((actual[4] as u16) << 8) | actual[5] as u16,
                            ((actual[6] as u16) << 8) | actual[7] as u16,
                            ((actual[8] as u16) << 8) | actual[9] as u16,
                            ((actual[10] as u16) << 8) | actual[11] as u16,
                            ((actual[12] as u16) << 8) | actual[13] as u16,
                            ((actual[14] as u16) << 8) | actual[15] as u16];
            segments == addr.segments()
        }
        _ => false,
    }
}

#[cfg(test)]
mod test {
    use openssl::ssl::{SslContext, SslMethod, IntoSsl, SslStream, SSL_VERIFY_PEER};
    use openssl::ssl::error::SslError;
    use std::io;
    use std::net::TcpStream;
    use std::process::{Command, Child, Stdio};
    use std::sync::atomic::{AtomicUsize, ATOMIC_USIZE_INIT, Ordering};
    use std::thread;
    use std::time::Duration;

    use super::*;

    static NEXT_PORT: AtomicUsize = ATOMIC_USIZE_INIT;

    struct Server {
        child: Child,
        port: u16,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.child.kill();
        }
    }

    impl Server {
        fn start(cert: &str, key: &str) -> Server {
            let port = 15410 + NEXT_PORT.fetch_add(1, Ordering::SeqCst) as u16;

            let child = Command::new("openssl")
                            .arg("s_server")
                            .arg("-accept")
                            .arg(port.to_string())
                            .arg("-cert")
                            .arg(cert)
                            .arg("-key")
                            .arg(key)
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .stdin(Stdio::piped())
                            .spawn()
                            .unwrap();

            Server {
                child: child,
                port: port,
            }
        }
    }

    fn connect(cert: &str, key: &str) -> (Server, TcpStream) {
        let server = Server::start(cert, key);

        for _ in 0..20 {
            match TcpStream::connect(("localhost", server.port)) {
                Ok(s) => return (server, s),
                Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(e) => panic!("failed to connect: {}", e),
            }
        }
        panic!("server never came online");
    }

    fn negotiate(cert: &str, key: &str, domain: &str) -> Result<SslStream<TcpStream>, SslError> {
        let (_server, stream) = connect(cert, key);

        let mut ctx = SslContext::new(SslMethod::Sslv23).unwrap();
        ctx.set_CA_file(cert).unwrap();
        let mut ssl = ctx.into_ssl().unwrap();

        let domain = domain.to_owned();
        ssl.set_verify(SSL_VERIFY_PEER, move |p, x| verify_callback(&domain, p, x));

        SslStream::connect(ssl, stream)
    }

    #[test]
    fn google_valid() {
        let stream = TcpStream::connect("google.com:443").unwrap();
        let mut ctx = SslContext::new(SslMethod::Sslv23).unwrap();
        ctx.set_default_verify_paths().unwrap();
        let mut ssl = ctx.into_ssl().unwrap();

        ssl.set_verify(SSL_VERIFY_PEER, |p, x| verify_callback("google.com", p, x));

        SslStream::connect(ssl, stream).unwrap();
    }

    #[test]
    fn google_bad_domain() {
        let stream = TcpStream::connect("google.com:443").unwrap();
        let mut ctx = SslContext::new(SslMethod::Sslv23).unwrap();
        ctx.set_default_verify_paths().unwrap();
        let mut ssl = ctx.into_ssl().unwrap();

        ssl.set_verify(SSL_VERIFY_PEER, |p, x| verify_callback("foo.com", p, x));

        SslStream::connect(ssl, stream).unwrap_err();
    }

    #[test]
    fn valid_sname() {
        negotiate("test/valid-sn.cert.pem",
                  "test/valid-sn.key.pem",
                  "foobar.com")
            .unwrap();
    }

    #[test]
    fn invalid_sname() {
        negotiate("test/valid-sn.cert.pem",
                  "test/valid-sn.key.pem",
                  "fizzbuzz.com")
            .unwrap_err();
    }

    #[test]
    fn sans_prefered_to_cn() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "foobar.com")
            .unwrap_err();
    }

    #[test]
    fn valid_double_wildcard() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "headfootail.doublewild.com")
            .unwrap();
    }

    #[test]
    fn valid_double_wildcard_minimal() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "headtail.doublewild.com")
            .unwrap();
    }

    #[test]
    fn invalid_double_wildcard_footer() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "headfootaill.doublewild.com")
            .unwrap_err();
    }

    #[test]
    fn invalid_double_wildcard_header() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "bheadfootaill.doublewild.com")
            .unwrap_err();
    }

    #[test]
    fn valid_tail_wildcard() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "footail.tailwild.com")
            .unwrap();
    }

    #[test]
    fn valid_tail_wildcard_minimal() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "tail.tailwild.com")
            .unwrap();
    }

    #[test]
    fn invalid_tail_wildcard() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "footaill.tailwild.com")
            .unwrap_err();
    }

    #[test]
    fn valid_head_wildcard() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "headfoo.headwild.com")
            .unwrap();
    }

    #[test]
    fn valid_head_wildcard_minimal() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "head.headwild.com")
            .unwrap();
    }

    #[test]
    fn invalid_head_wildcard() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "bheadfoo.headwild.com")
            .unwrap_err();
    }

    #[test]
    fn valid_bare_wildcard() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "foo.barewild.com")
            .unwrap();
    }

    #[test]
    fn invalid_wildcard_too_deep() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "bar.foo.barewild.com")
            .unwrap_err();
    }

    #[test]
    fn invalid_wildcard_too_short() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "barewild.com")
            .unwrap_err();
    }

    #[test]
    fn valid_ipv4() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "192.168.1.1")
            .unwrap();
    }

    #[test]
    fn invalid_ipv4() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "192.168.1.2")
            .unwrap_err();
    }

    #[test]
    fn valid_ipv6() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "2001:DB8:85A3:0:0:8A2E:370:7334")
            .unwrap();
    }

    #[test]
    fn invalid_ipv6() {
        negotiate("test/valid-san.cert.pem",
                  "test/valid-san.key.pem",
                  "2001:DB8:85A3:0:0:8A2E:370:7335")
            .unwrap_err();
    }

    #[test]
    fn bogus_wildcard_not_last() {
        negotiate("test/invalid-san.cert.pem",
                  "test/invalid-san.key.pem",
                  "server1.foo.example.com")
            .unwrap_err();
    }

    #[test]
    fn bogus_wildcard_too_short() {
        negotiate("test/invalid-san.cert.pem",
                  "test/invalid-san.key.pem",
                  "foo.com")
            .unwrap_err();
    }
}
