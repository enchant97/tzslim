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
//! {"hash":"<sha256 hex of every byte above>","sig":null}
//! ```
//!
//! The trailer is always the LAST line. `hash` covers every byte before it,
//! including the newline ending the last data line. With `--sign`, `sig` is
//! filled in instead of null:
//!
//! ```text
//! {"hash":"...","sig":{"alg":"ed25519","val":"<base64>","key":"<sha256 hex of public key>","timestamp":1767225600}}
//! ```
//!
//! The ed25519 signature is made over the 32 raw bytes of the SHA-256 digest
//! followed by `timestamp` as an 8-byte big-endian unsigned integer.

use std::fs::{self, File};
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{Signer as _, SigningKey};
use jiff::{
    Span, Timestamp,
    tz::{TimeZone, TimeZoneDatabase},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// --------------------------------------------------------------------------
// CLI
// --------------------------------------------------------------------------
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an ed25519 keypair
    Keygen,
    /// Generate the static site
    Build(BuildArgs),
}

#[derive(Args)]
struct BuildArgs {
    /// Output directory
    #[arg(long, default_value = "dist/v1")]
    out: PathBuf,

    /// How many calendar years of future transitions to include
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..=100))]
    years: u16,

    /// Sign every file with ed25519 (needs a signing key). Without it the
    /// trailer carries the hash only and "sig" is null
    #[arg(long)]
    sign: bool,

    /// Base64 ed25519 private key (32 bytes). Prefer the environment variable
    /// or --signing-key-file so the key stays out of the process list.
    #[arg(
        long,
        env = "TZ_SIGNING_KEY",
        hide_env_values = true,
        conflicts_with = "signing_key_file"
    )]
    signing_key: Option<String>,

    /// File containing the base64 ed25519 private key (surrounding whitespace is ignored)
    #[arg(long, env = "TZ_SIGNING_KEY_FILE")]
    signing_key_file: Option<PathBuf>,

    /// Use this directory of compiled TZif files instead of downloading
    #[arg(long)]
    tzdata_dir: Option<PathBuf>,

    /// Use the database compiled into this binary (build with `--features tzdata-bundled`)
    #[arg(long, conflicts_with = "tzdata_dir")]
    tzdata_bundled: bool,

    /// Where downloaded databases are cached
    #[arg(long, default_value = ".tzdata-cache")]
    cache_dir: PathBuf,
}

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

#[derive(Serialize)]
struct IndexRow<'a> {
    /// Zone name
    n: &'a str,
    /// First 16 hex chars of the SHA-256 of the zone body
    h: String,
}

/// Final line of every file: a hash of everything above it, plus an optional
/// signature over that hash.
#[derive(Serialize)]
struct Trailer {
    /// Lowercase hex SHA-256 of every byte above this line, including the
    /// newline ending the last data line. Always present
    hash: String,
    /// ed25519 signature, or null when the build was not signed
    sig: Option<Signature>,
}

/// Signature over `raw SHA-256 digest (32 bytes) || timestamp (8 bytes, big-endian)`.
#[derive(Serialize)]
struct Signature {
    /// Algorithm, currently always "ed25519"
    alg: &'static str,
    /// Base64 signature
    val: String,
    /// Lowercase hex SHA-256 of the raw 32-byte public key. Lets a device
    /// pick the right key from the ones it trusts (e.g. during key rotation)
    key: String,
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
/// Lowercase hex SHA-256 of a raw public key, used as the key id in signatures.
fn key_id(public_key: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(public_key))
}

/// An ed25519 signing key together with its id.
struct Signer {
    key: SigningKey,
    /// Lowercase hex SHA-256 of the public key
    key_id: String,
}

/// Produces the trailer line. It always hashes the body and signs it only
/// when a signing key was supplied.
struct Integrity {
    /// None means files are written with `"sig": null`
    signer: Option<Signer>,
    /// Creation time (Unix seconds) written into every signature of this run
    created: u64,
}

impl Integrity {
    fn new(key_b64: Option<&str>, created: u64) -> Result<Self> {
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
        Ok(Self { signer, created })
    }

    fn trailer(&self, body: &[u8]) -> Trailer {
        let digest = Sha256::digest(body);
        let sig = self.signer.as_ref().map(|s| {
            // Signed message: raw digest bytes, then the timestamp big-endian.
            let mut msg = Vec::with_capacity(40);
            msg.extend_from_slice(&digest);
            msg.extend_from_slice(&self.created.to_be_bytes());
            Signature {
                alg: "ed25519",
                val: B64.encode(s.key.sign(&msg).to_bytes()),
                key: s.key_id.clone(),
                timestamp: self.created,
            }
        });
        Trailer {
            hash: hex::encode(digest),
            sig,
        }
    }

    /// Append the trailer as the final NDJSON line (always present).
    /// Returns the finished file bytes and the trailer that was written.
    fn seal(&self, mut body: Vec<u8>) -> Result<(Vec<u8>, Trailer)> {
        let trailer = self.trailer(&body);
        push_line(&mut body, &trailer)?;
        Ok((body, trailer))
    }
}

// --------------------------------------------------------------------------
// Database acquisition
// --------------------------------------------------------------------------
const PYPI_URL: &str = "https://pypi.org/pypi/tzdata/json";

#[derive(Deserialize)]
struct PypiMeta {
    info: PypiInfo,
    urls: Vec<PypiFile>,
}
#[derive(Deserialize)]
struct PypiInfo {
    version: String,
}
#[derive(Deserialize)]
struct PypiFile {
    filename: String,
    url: String,
    packagetype: String,
    digests: PypiDigests,
}
#[derive(Deserialize)]
struct PypiDigests {
    sha256: String,
}

/// Return a directory of TZif files for the latest release, downloading it
/// into `cache` if needed.
fn ensure_database(cache: &Path) -> Result<PathBuf> {
    let meta: PypiMeta = ureq::get(PYPI_URL)
        .call()
        .context("could not reach PyPI (use --tzdata-dir to work offline)")?
        .into_body()
        .read_json()?;
    let file = meta
        .urls
        .iter()
        .find(|f| f.packagetype == "bdist_wheel" && f.filename.ends_with(".whl"))
        .context("no wheel published for the tzdata package")?;

    let final_dir = cache.join(format!("tzdata-{}", meta.info.version));
    let zoneinfo = final_dir.join("zoneinfo");
    if zoneinfo.is_dir() {
        eprintln!("using cached {}", final_dir.display());
        return Ok(zoneinfo);
    }

    eprintln!("downloading {}", file.filename);
    let mut wheel = Vec::new();
    ureq::get(&file.url)
        .call()?
        .into_body()
        .into_reader()
        .read_to_end(&mut wheel)?;

    let digest = hex::encode(Sha256::digest(&wheel));
    if !digest.eq_ignore_ascii_case(&file.digests.sha256) {
        bail!("SHA-256 mismatch for {}: got {digest}", file.filename);
    }

    let tmp = cache.join(format!(".partial-{}", meta.info.version));
    if tmp.exists() {
        fs::remove_dir_all(&tmp)?;
    }
    extract_zoneinfo(&wheel, &tmp)?;
    fs::rename(&tmp, &final_dir)?;
    Ok(zoneinfo)
}

/// Unpack `tzdata/zoneinfo/**` from the wheel into `<dest>/zoneinfo/**`.
fn extract_zoneinfo(wheel: &[u8], dest: &Path) -> Result<()> {
    let mut zip = zip::ZipArchive::new(Cursor::new(wheel))?;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        if entry.is_dir() {
            continue;
        }
        // enclosed_name() rejects absolute paths and ".." traversal.
        let Some(path) = entry.enclosed_name() else {
            continue;
        };
        let Ok(rel) = path.strip_prefix("tzdata/zoneinfo") else {
            continue;
        };
        let out = dest.join("zoneinfo").join(rel);
        fs::create_dir_all(out.parent().unwrap())?;
        io::copy(&mut entry, &mut File::create(&out)?)?;
    }
    Ok(())
}

/// Pick the database: bundled, a local directory, or the latest download.
/// Returns the database, its IANA version and a description for messages.
fn open_database(args: &BuildArgs) -> Result<(TimeZoneDatabase, String, String)> {
    if args.tzdata_bundled {
        let (db, version) = bundled_database()?;
        return Ok((db, version, "the bundled database".into()));
    }
    let dir = match &args.tzdata_dir {
        Some(d) => d.clone(),
        None => ensure_database(&args.cache_dir)?,
    };
    let version = iana_version(&dir);
    let db = TimeZoneDatabase::from_dir(&dir)
        .with_context(|| format!("could not read zone files in {}", dir.display()))?;
    Ok((db, version, dir.display().to_string()))
}

#[cfg(feature = "tzdata-bundled")]
fn bundled_database() -> Result<(TimeZoneDatabase, String)> {
    let version = jiff_tzdb::VERSION.unwrap_or("unknown").to_owned();
    Ok((TimeZoneDatabase::bundled(), version))
}

#[cfg(not(feature = "tzdata-bundled"))]
fn bundled_database() -> Result<(TimeZoneDatabase, String)> {
    bail!(
        "this binary has no bundled database; rebuild with `cargo build --release --features bundled`"
    )
}

/// The first line of tzdata.zi looks like "# version 2026b".
fn iana_version(dir: &Path) -> String {
    fs::read_to_string(dir.join("tzdata.zi"))
        .ok()
        .and_then(|s| {
            s.lines()
                .next()
                .and_then(|l| l.strip_prefix("# version "))
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".into())
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
    println!("{}", key_id(&public));
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
    let integrity = Integrity::new(key.as_deref(), created.as_second().try_into()?)?;

    let (db, version, source) = open_database(&args)?;

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
        index.push((name.as_str(), trailer.hash[..16].to_owned()));
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
    match Cli::parse().command {
        Command::Keygen => keygen(),
        Command::Build(args) => build(args),
    }
}
