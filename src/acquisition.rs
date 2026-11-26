use std::{
    fs::{self, File},
    io::{self, Cursor, Read},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use jiff::tz::TimeZoneDatabase;
use serde::Deserialize;
use sha2::{Digest, Sha256};

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

/// Pick the database: bundled, a local directory, or the latest download.
/// Returns the database, its IANA version and a description for messages.
pub fn open_database(
    use_bundled: bool,
    tzdata_dir: Option<PathBuf>,
    cache_dir: PathBuf,
) -> Result<(TimeZoneDatabase, String, String)> {
    if use_bundled {
        let (db, version) = bundled_database()?;
        return Ok((db, version, "the bundled database".into()));
    }
    let dir = match &tzdata_dir {
        Some(d) => d.clone(),
        None => ensure_database(&cache_dir)?,
    };
    let version = iana_version(&dir);
    let db = TimeZoneDatabase::from_dir(&dir)
        .with_context(|| format!("could not read zone files in {}", dir.display()))?;
    Ok((db, version, dir.display().to_string()))
}
