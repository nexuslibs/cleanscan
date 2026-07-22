use anyhow::{anyhow, Context, Result};
use flate2::read::GzDecoder;
use reqwest::{Client, StatusCode};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    io::{Cursor, Read},
    path::Path,
    sync::mpsc::Receiver,
    time::Duration,
};
use tar::Archive;

const API_URL: &str = "https://api.github.com/repos/nexuslibs/cleanscan/releases/latest";
const REPOSITORY: &str = "nexuslibs/cleanscan";
const BINARY: &str = "cleanscan";

#[derive(Debug, Clone, Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Debug, Clone, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpdateInfo {
    version: Version,
    tag: String,
}

fn client() -> Result<Client> {
    Ok(Client::builder()
        .user_agent(concat!("cleanscan/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(4))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()?)
}

async fn latest_release(endpoint: &str) -> Result<Release> {
    let response = client()?.get(endpoint).send().await?;
    if response.status() != StatusCode::OK {
        anyhow::bail!("release service returned {}", response.status());
    }
    response.json().await.context("invalid release metadata")
}

fn parse_version(tag: &str) -> Result<Version> {
    Version::parse(tag.strip_prefix('v').unwrap_or(tag))
        .with_context(|| format!("release tag is not a semantic version: {tag}"))
}

fn release_update(release: &Release) -> Result<UpdateInfo> {
    Ok(UpdateInfo {
        version: parse_version(&release.tag_name)?,
        tag: release.tag_name.clone(),
    })
}

fn target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-musl"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-musl"),
        ("linux", "arm") => Some("armv7-unknown-linux-musleabihf"),
        ("linux", "x86") => Some("i686-unknown-linux-musl"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        _ => None,
    }
}

fn asset<'a>(release: &'a Release, name: &str) -> Result<&'a Asset> {
    release
        .assets
        .iter()
        .find(|asset| asset.name == name)
        .ok_or_else(|| anyhow!("release {} does not contain {name}", release.tag_name))
}

fn fixed_asset_url(tag: &str, name: &str, url: &str) -> Result<()> {
    let expected = format!("https://github.com/{REPOSITORY}/releases/download/{tag}/{name}");
    if url != expected {
        anyhow::bail!("release asset URL is not the expected GitHub URL");
    }
    Ok(())
}

fn checksum(value: &[u8]) -> Result<[u8; 32]> {
    let token = std::str::from_utf8(value)?
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("checksum asset is empty"))?;
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("checksum asset does not contain a 64-character hexadecimal digest");
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in token.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex(pair[0])? << 4) | hex(pair[1])?;
    }
    Ok(digest)
}

fn hex(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(anyhow!("invalid hexadecimal digit")),
    }
}

fn extract_binary(bytes: &[u8]) -> Result<Vec<u8>> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    let mut binary = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path != Path::new(BINARY) || !entry.header().entry_type().is_file() {
            anyhow::bail!(
                "release archive contains an unexpected entry: {}",
                path.display()
            );
        }
        if binary.is_some() {
            anyhow::bail!("release archive contains duplicate binaries");
        }
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;
        binary = Some(contents);
    }
    binary.ok_or_else(|| anyhow!("release archive does not contain {BINARY}"))
}

async fn download(client: &Client, asset: &Asset, tag: &str) -> Result<Vec<u8>> {
    fixed_asset_url(tag, &asset.name, &asset.browser_download_url)?;
    let response = client.get(&asset.browser_download_url).send().await?;
    if response.status() != StatusCode::OK {
        anyhow::bail!("download of {} returned {}", asset.name, response.status());
    }
    Ok(response.bytes().await?.to_vec())
}

fn current_version() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("package version must be valid semver")
}

async fn check(endpoint: &str) -> Result<Option<UpdateInfo>> {
    let update = release_update(&latest_release(endpoint).await?)?;
    Ok((update.version > current_version()).then_some(update))
}

pub type UpdateReceiver = Receiver<String>;

pub fn start_background_check() -> UpdateReceiver {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let Some(update) = tokio::runtime::Runtime::new()
            .ok()
            .and_then(|runtime| runtime.block_on(check(API_URL)).ok().flatten())
        else {
            return;
        };
        let _ = sender.send(format!(
            "Update available: cleanscan v{} (run `cleanscan update`)",
            update.version
        ));
    });
    receiver
}

pub fn run_explicit(check_only: bool) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let release = latest_release(API_URL).await?;
        let update = release_update(&release)?;
        if update.version <= current_version() {
            println!("cleanscan v{} is up to date", current_version());
            return Ok(());
        }
        if check_only {
            println!("Update available: cleanscan v{}", update.version);
            return Ok(());
        }
        install(&release, &update).await
    })
}

async fn install(release: &Release, update: &UpdateInfo) -> Result<()> {
    let target = target().ok_or_else(|| anyhow!("no release artifact for this platform"))?;
    let archive_name = format!("{BINARY}-{target}.tar.gz");
    let checksum_name = format!("{archive_name}.sha256");
    let archive_asset = asset(release, &archive_name)?;
    let checksum_asset = asset(release, &checksum_name)?;
    let client = client()?;
    let archive = download(&client, archive_asset, &update.tag).await?;
    let expected = checksum(&download(&client, checksum_asset, &update.tag).await?)?;
    let actual: [u8; 32] = Sha256::digest(&archive).into();
    if actual != expected {
        anyhow::bail!("checksum mismatch for {archive_name}");
    }
    replace_current_executable(&extract_binary(&archive)?, &update.version)
}

fn replace_current_executable(binary: &[u8], version: &Version) -> Result<()> {
    let executable = std::env::current_exe().context("cannot locate current executable")?;
    let parent = executable
        .parent()
        .ok_or_else(|| anyhow!("current executable has no parent directory"))?;
    let temp = parent.join(format!(".{BINARY}.update-{}", std::process::id()));
    let result = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .with_context(|| format!("cannot create update file in {}", parent.display()))?;
        use std::io::Write;
        file.write_all(binary)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o755))?;
        }
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, &executable).with_context(|| {
            format!(
                "cannot replace executable {}; check permissions",
                executable.display()
            )
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result.map(|_| println!("Updated cleanscan to v{version}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str, assets: Vec<Asset>) -> Release {
        Release {
            tag_name: tag.into(),
            assets,
        }
    }

    #[test]
    fn versions_compare_semantically() {
        assert!(parse_version("v1.2.0").unwrap() > parse_version("1.1.9").unwrap());
        assert!(parse_version("v1.2.0-beta.1").unwrap() < parse_version("v1.2.0").unwrap());
        assert_eq!(
            parse_version(env!("CARGO_PKG_VERSION")).unwrap(),
            current_version()
        );
    }

    #[test]
    fn malformed_release_is_rejected() {
        assert!(release_update(&release("latest", Vec::new())).is_err());
    }

    #[test]
    fn checksum_requires_valid_hex() {
        assert!(checksum(b"not-a-digest").is_err());
        let digest =
            checksum(b"0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        assert_eq!(digest, [0; 32]);
    }

    fn archive_with(name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        let encoder = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let content = b"binary";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, name, &content[..])
            .unwrap();
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();
        bytes
    }

    #[test]
    fn archive_accepts_only_the_binary() {
        assert_eq!(extract_binary(&archive_with(BINARY)).unwrap(), b"binary");
    }

    #[test]
    fn unexpected_archive_entry_is_rejected() {
        assert!(extract_binary(&archive_with("other")).is_err());
    }

    #[tokio::test]
    async fn unavailable_release_service_is_reported_to_explicit_callers() {
        let result = latest_release("http://127.0.0.1:9/latest").await;
        assert!(result.is_err());
    }
}
