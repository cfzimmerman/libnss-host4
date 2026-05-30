# libnss-host4

[![crates.io](https://img.shields.io/crates/v/libnss-host4.svg)](https://crates.io/crates/libnss-host4)
[![docs.rs](https://img.shields.io/docsrs/libnss-host4)](https://docs.rs/libnss-host4)
[![CI](https://github.com/cfzimmerman/libnss-host4/actions/workflows/ci.yml/badge.svg)](https://github.com/cfzimmerman/libnss-host4/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/libnss-host4.svg)](#license)

Implementing the trait and macro in this crate will expose a
`gethostbyname4_r` FFI hook for NSS in your Rust `cdylib`.

### Example

```rust
use libnss_host4::{Addr, HostResolver, err::NssErr, impl_gethostbyname4_r};
use std::net::Ipv6Addr;

/// This resolver maps "localhost" to [::1%0].
struct LocalDns;
impl_gethostbyname4_r!(local, LocalDns);

impl HostResolver for LocalDns {
    fn resolve_host(hostname: &str) -> Result<impl IntoIterator<Item = Addr>, NssErr> {
        if hostname == "localhost" {
            return Ok([Addr {
                ip: Ipv6Addr::LOCALHOST.into(),
                scope_id: 0,
            }]);
        }
        Err(NssErr::NO_RESULT)
    }
}
```

See [examples/nss_example.rs](https://github.com/cfzimmerman/libnss-host4/blob/main/examples/nss_example.rs) and [Cargo.toml](https://github.com/cfzimmerman/libnss-host4/blob/main/Cargo.toml) for more info.

Building the example as an NSS module requires the `[[example]]` `crate-type = ["cdylib"]`
declaration shown in [Cargo.toml](https://github.com/cfzimmerman/libnss-host4/blob/main/Cargo.toml).

### Background

glibc defines a Name Service Switch interface for querying hostnames.

<https://sourceware.org/glibc/manual/2.43/html_mono/libc.html#Host-Names>

This once-simple lookup API has unfortunately degenerated into a sedimentary
chaos of numbered functions differentiated by reentrance and lack thereof.
An early indication of which is the conspicuous absence of `gethostbyname3_r`
and `gethostbyname4_r` in the docs linked above.

However, as of writing, `gethostbyname4_r` is the only NSS host hook that
can return IPv6 addresses with a `scope_id`, which makes it a big deal
for the chosen few who care about such things.

Other Rust NSS usage is already well supported by the [libnss crate](https://crates.io/crates/libnss).
The motivating cause for this crate cannot accomodate its GPL license,
which is why this is standalone. Presumably both crates can be used in
the same `cdylib` to cover the full NSS host API.

If the other hooks aren't needed, though, a cdylib with just `gethostbyname4_r`
is sufficient for `getaddrinfo`-based resolution via `/etc/nsswitch.conf`.

### License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
