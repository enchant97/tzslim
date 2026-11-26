//! Generate compact per-zone timezone files (NDJSON) for microcontrollers.
//!
//! The timezone database is NOT compiled in. On every run the tool looks up the
//! latest release of the `tzdata` package on PyPI (precompiled TZif files, the
//! same data IANA publishes), downloads it if it is not already cached, checks
//! its SHA-256 against the digest PyPI reports, and reads it at runtime.
//! Use `--tzdata-dir` to point at any directory of compiled TZif files instead
//! (e.g. /usr/share/zoneinfo, or the output of `zic`), or `--tzdata-bundled`
//! to use the database compiled into the binary (needs `--features bundled`).
//!
//! Zone file (site/v1/Europe/London.ndjson):
//!
//! ```text
//! {"v":"2026b","n":"Europe/London","a":"GMT","o":0,"u":1924991999}
//! {"t":1774832400,"o":3600,"a":"BST"}
//! {"t":1792976400,"o":0,"a":"GMT"}
//! {"hash":"<base64 sha256 of every byte above>","sig":null}
//! ```
//!
//! The trailer is always the LAST line. `hash` covers every byte before it,
//! including the newline ending the last data line. With `--sign`, `sig` is
//! filled in instead of null:
//!
//! ```text
//! {"hash":"...","sig":{"alg":"ed25519","val":"<base64>","key":"<base64 sha256 of public key>","timestamp":1767225600}}
//! ```
//!
//! The ed25519 signature is made over the 32 raw bytes of the SHA-256 digest
//! followed by `timestamp` as an 8-byte big-endian unsigned integer.

mod acquisition;
mod args;

use std::fs;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signer as _, SigningKey};
use jiff::{Span, Timestamp, tz::TimeZone};
use serde::Serialize;
use serde_with::{base64::Base64, serde_as};
use sha2::{Digest, Sha256};

use crate::{
    acquisition::open_database,
    args::{BuildArgs, Cli, Command},
};

// --------------------------------------------------------------------------
// Data model (serialised one JSON object per line)
// --------------------------------------------------------------------------
#[derive(Serialize)]
struct Transition {
    /// Unix epoch seconds
    t: i64,
    /// Total UTC offset in seconds from this moment on
    o: i32,
    /// Abbreviation, e.g. "BST"
    a: String,
}

#[derive(Serialize)]
struct ZoneHeader<'a> {
    /// tzdata release, e.g. "2026b"
    v: &'a str,
    /// IANA name
    n: &'a str,
    /// Abbreviation in effect at generation time
    a: String,
    /// Total UTC offset in effect at generation time
    o: i32,
    /// Data is valid up to here; refetch after
    u: i64,
}

struct ZoneDoc<'a> {
    header: ZoneHeader<'a>,
    transitions: Vec<Transition>,
}

impl ZoneDoc<'_> {
    fn body(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        push_line(&mut buf, &self.header)?;
        for t in &self.transitions {
            push_line(&mut buf, t)?;
        }
        Ok(buf)
    }
}

/// First line of index.ndjson.
#[derive(Serialize)]
struct IndexHeader<'a> {
    /// tzdata release the whole site was generated from, e.g. "2026b"
    tzdata: &'a str,
    /// Unix epoch seconds when the site was generated (the same value as the
    /// timestamp in every signature of the run)
    generated: i64,
}

#[serde_as]
#[derive(Serialize)]
struct IndexRow<'a> {
    /// Zone name
    n: &'a str,
    #[serde_as(as = "Base64")]
    /// SHA-256 of the zone body
    h: Box<[u8]>,
}

/// A hash of everything above it.
///
/// Goes after tz-data, but before signatures
#[serde_as]
#[derive(Serialize)]
struct IntegrityTrailer {
    /// SHA-256 of every byte above this line, including the
    /// newline ending the last data line. Always present
    #[serde_as(as = "Base64")]
    hash: Box<[u8]>,
}

impl IntegrityTrailer {
    fn sign(&self, signer: &Signer) -> Signature<'_> {
        let timestamp: u64 = Timestamp::now().as_second().try_into().unwrap();
        // Signed message: raw digest bytes, then the timestamp big-endian.
        let mut msg = Vec::with_capacity(40);
        msg.extend_from_slice(&self.hash);
        msg.extend_from_slice(&timestamp.to_be_bytes());
        Signature {
            alg: "ed25519",
            val: Box::new(signer.key.sign(&msg).to_bytes()),
            kid: signer.key_id.clone(),
            timestamp,
        }
    }
}

/// Signature over `raw SHA-256 digest (32 bytes) || timestamp (8 bytes, big-endian)`.
#[serde_as]
#[derive(Serialize)]
struct Signature<'a> {
    /// Algorithm, currently always "ed25519"
    alg: &'a str,
    /// raw signature
    #[serde_as(as = "Base64")]
    val: Box<[u8]>,
    /// SHA-256 of the raw public key. Lets a device
    /// pick the right key from the ones it trusts (e.g. during key rotation)
    #[serde_as(as = "Base64")]
    kid: Box<[u8]>,
    /// Creation time in Unix epoch seconds, shared by every file in one run.
    /// It is part of the signed message, so it cannot be altered; devices can
    /// use it to reject data older than what they already hold
    timestamp: u64,
}

fn push_line<T: Serialize>(buf: &mut Vec<u8>, value: &T) -> Result<()> {
    serde_json::to_writer(&mut *buf, value)?;
    buf.push(b'\n');
    Ok(())
}

// --------------------------------------------------------------------------
// Integrity / signing
// --------------------------------------------------------------------------
/// SHA-256 of a raw public key, used as the key id in signatures.
fn key_id(public_key: &[u8; 32]) -> Box<[u8]> {
    Sha256::digest(public_key).to_vec().into_boxed_slice()
}

/// An ed25519 signing key together with its id.
struct Signer {
    key: SigningKey,
    /// SHA-256 of the public key
    key_id: Box<[u8]>,
}

/// Produces the trailer line. It always hashes the body and signs it only
/// when a signing key was supplied.
struct Integrity {
    /// None means files are written with `"sig": null`
    signer: Option<Signer>,
}

impl Integrity {
    fn new(key_b64: Option<&str>) -> Result<Self> {
        let signer = key_b64
            .map(|raw| -> Result<Signer> {
                let bytes = B64
                    .decode(raw.trim())
                    .context("signing key is not valid base64")?;
                let seed: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("signing key must be exactly 32 bytes"))?;
                let key = SigningKey::from_bytes(&seed);
                let key_id = key_id(&key.verifying_key().to_bytes());
                Ok(Signer { key, key_id })
            })
            .transpose()?;
        Ok(Self { signer })
    }

    fn trailer(&self, body: &[u8]) -> IntegrityTrailer {
        let digest = Sha256::digest(body);
        IntegrityTrailer {
            hash: digest.to_vec().into_boxed_slice(),
        }
    }

    /// Append the trailer as the final NDJSON line (always present).
    /// Returns the finished file bytes and the trailer that was written.
    fn seal(&self, mut body: Vec<u8>) -> Result<(Vec<u8>, IntegrityTrailer)> {
        let trailer = self.trailer(&body);
        push_line(&mut body, &trailer)?;
        if let Some(signer) = &self.signer {
            let signature = trailer.sign(signer);
            push_line(&mut body, &signature)?;
        }
        Ok((body, trailer))
    }
}

// --------------------------------------------------------------------------
// Commands
// --------------------------------------------------------------------------
fn keygen() -> Result<()> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("rng failure: {e}"))?;
    let key = SigningKey::from_bytes(&seed);
    println!("TZ_SIGNING_KEY (keep secret, store as a CI secret):");
    println!("{}", B64.encode(seed));
    println!("Public key (embed on the device):");
    let public = key.verifying_key().to_bytes();
    println!("{}", B64.encode(public));
    println!("Key id (SHA-256 of the public key, appears as \"key\" in signatures):");
    println!("{}", B64.encode(key_id(&public)));
    Ok(())
}

fn build(args: BuildArgs) -> Result<()> {
    // One creation time for the whole run; it goes into every signature.
    let created = Timestamp::now();

    let key = if args.sign {
        Some(match &args.signing_key_file {
            Some(path) => fs::read_to_string(path)
                .with_context(|| format!("could not read signing key file {}", path.display()))?,
            None => args.signing_key.clone().context(
                "--sign needs --signing-key-file, --signing-key, $TZ_SIGNING_KEY_FILE or $TZ_SIGNING_KEY",
            )?,
        })
    } else {
        None
    };
    let integrity = Integrity::new(key.as_deref())?;

    let (db, version, source) =
        open_database(args.tzdata_bundled, args.tzdata_dir, args.cache_dir)?;

    // Transitions are listed from the creation time up to this many calendar years later.
    let end = created
        .to_zoned_datetime(TimeZone::UTC)
        .checked_add(Span::new().years(i64::from(args.years)))?
        .timestamp()
        .as_second();

    let mut names: Vec<String> = db.available().map(|n| n.as_str().to_owned()).collect();
    names.sort();
    if names.is_empty() {
        bail!("no zones found in {source}");
    }

    let mut index = Vec::with_capacity(names.len());
    for name in &names {
        let tz = db.get(name).with_context(|| format!("loading {name}"))?;

        let info = tz.to_offset_info(created);
        let (mut cur_off, mut cur_abbr) = (info.offset().seconds(), info.abbreviation().to_owned());
        let header = ZoneHeader {
            v: &version,
            n: name,
            a: cur_abbr.clone(),
            o: cur_off,
            u: end,
        };

        // Only keep transitions that change what a device would display.
        let mut transitions = Vec::new();
        for tr in tz
            .following(created)
            .take_while(|t| t.timestamp().as_second() < end)
        {
            let (off, abbr) = (tr.offset().seconds(), tr.abbreviation());
            if off != cur_off || abbr != cur_abbr {
                transitions.push(Transition {
                    t: tr.timestamp().as_second(),
                    o: off,
                    a: abbr.to_owned(),
                });
                cur_off = off;
                cur_abbr = abbr.to_owned();
            }
        }

        let (file, trailer) = integrity.seal(
            ZoneDoc {
                header,
                transitions,
            }
            .body()?,
        )?;

        let path = args.out.join(format!("{name}.ndjson"));
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(&path, file)?;
        index.push((name.as_str(), trailer.hash));
    }

    let mut body = Vec::new();
    push_line(
        &mut body,
        &IndexHeader {
            tzdata: &version,
            generated: created.as_second(),
        },
    )?;
    for (n, h) in index {
        push_line(&mut body, &IndexRow { n, h })?;
    }
    fs::write(args.out.join("index.ndjson"), integrity.seal(body)?.0)?;

    eprintln!(
        "wrote {} zones to {} (tzdata {version})",
        names.len(),
        args.out.display()
    );
    Ok(())
}

fn main() -> Result<()> {
    match Cli::get_cli().command {
        Command::Keygen => keygen(),
        Command::Build(args) => build(args),
    }
}
