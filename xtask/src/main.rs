use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use time::OffsetDateTime;

const CA_CERT: &str = "ca.pem";
const CA_KEY: &str = "ca.key";
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Parser)]
#[command(name = "xtask", about = "magicTunnel development tasks")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Generate a dev CA (reused if it already exists) and node certificates signed by it.
    ///
    /// Without --server/--client, generates servers `relay1`, `exit1` and client `client1`,
    /// matching config/*.example.toml.
    GenCerts {
        /// Output directory.
        #[arg(long, default_value = "certs")]
        out: PathBuf,

        /// Server node as `NAME[=SAN,SAN,...]`; NAME is always a DNS SAN. Extra SANs may be
        /// IPs or DNS names. Repeatable.
        #[arg(long = "server", value_name = "SPEC")]
        servers: Vec<String>,

        /// Client node name. Repeatable.
        #[arg(long = "client", value_name = "NAME")]
        clients: Vec<String>,

        /// Validity of node certificates, in days.
        #[arg(long, default_value_t = 365)]
        days: u64,

        /// Overwrite existing node certificates (never overwrites the CA).
        #[arg(long)]
        force: bool,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::GenCerts {
            out,
            mut servers,
            mut clients,
            days,
            force,
        } => {
            if servers.is_empty() && clients.is_empty() {
                servers = vec!["relay1".into(), "exit1".into()];
                clients = vec!["client1".into()];
            }
            gen_certs(&out, &servers, &clients, days, force)
        }
    }
}

fn gen_certs(
    out: &Path,
    servers: &[String],
    clients: &[String],
    days: u64,
    force: bool,
) -> anyhow::Result<()> {
    let servers = servers
        .iter()
        .map(|spec| parse_server_spec(spec))
        .collect::<anyhow::Result<Vec<_>>>()?;
    for name in clients {
        validate_name(name)?;
    }

    fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    let ca = load_or_create_ca(out)?;

    for (name, sans) in servers {
        // Servers also dial the next hop when relaying, so they need clientAuth too.
        let eku = [
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        issue_node(out, &ca, name, sans, &eku, days, force)?;
    }
    for name in clients {
        let eku = [ExtendedKeyUsagePurpose::ClientAuth];
        issue_node(out, &ca, name, vec![name.clone()], &eku, days, force)?;
    }
    Ok(())
}

fn load_or_create_ca(out: &Path) -> anyhow::Result<Issuer<'static, KeyPair>> {
    let cert_path = out.join(CA_CERT);
    let key_path = out.join(CA_KEY);

    if cert_path.exists() || key_path.exists() {
        let cert_pem = read(&cert_path)?;
        let key = KeyPair::from_pem(&read(&key_path)?)
            .with_context(|| format!("parsing {}", key_path.display()))?;
        let ca = Issuer::from_ca_cert_pem(&cert_pem, key)
            .with_context(|| format!("parsing {}", cert_path.display()))?;
        println!("using existing CA {}", cert_path.display());
        return Ok(ca);
    }

    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "magicTunnel Dev CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    set_validity(&mut params, 10 * 365);

    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    write(&cert_path, &cert.pem(), false)?;
    write(&key_path, &key.serialize_pem(), true)?;
    println!("created CA {}", cert_path.display());
    Ok(Issuer::new(params, key))
}

fn issue_node(
    out: &Path,
    ca: &Issuer<'_, KeyPair>,
    name: &str,
    sans: Vec<String>,
    eku: &[ExtendedKeyUsagePurpose],
    days: u64,
    force: bool,
) -> anyhow::Result<()> {
    let cert_path = out.join(format!("{name}.pem"));
    let key_path = out.join(format!("{name}.key"));
    if !force && (cert_path.exists() || key_path.exists()) {
        println!("skip {name}: already exists (use --force to overwrite)");
        return Ok(());
    }

    let mut params = CertificateParams::new(sans.clone())
        .with_context(|| format!("invalid SANs for {name}: {sans:?}"))?;
    params.distinguished_name.push(DnType::CommonName, name);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = eku.to_vec();
    params.use_authority_key_identifier_extension = true;
    set_validity(&mut params, days);

    let key = KeyPair::generate()?;
    let cert = params.signed_by(&key, ca)?;
    write(&cert_path, &cert.pem(), false)?;
    write(&key_path, &key.serialize_pem(), true)?;
    println!("issued {name} (SANs: {})", sans.join(", "));
    Ok(())
}

/// Returns the node name and its full SAN list (name first).
fn parse_server_spec(spec: &str) -> anyhow::Result<(&str, Vec<String>)> {
    let (name, rest) = spec.split_once('=').unwrap_or((spec, ""));
    validate_name(name)?;
    let mut sans = vec![name.to_owned()];
    for san in rest.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if san.parse::<IpAddr>().is_err() && !is_dns_name(san) {
            bail!("invalid SAN {san:?} in {spec:?}: expected an IP address or DNS name");
        }
        sans.push(san.to_owned());
    }
    Ok((name, sans))
}

/// Node names become file names and DNS SANs.
fn validate_name(name: &str) -> anyhow::Result<()> {
    if !is_dns_name(name) || name == CA_CERT.trim_end_matches(".pem") {
        bail!("invalid node name {name:?}: use [A-Za-z0-9.-], and not \"ca\"");
    }
    Ok(())
}

fn is_dns_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with(['.', '-'])
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

fn set_validity(params: &mut CertificateParams, days: u64) {
    let now = SystemTime::now();
    // Backdate slightly to tolerate clock skew between test machines.
    params.not_before = OffsetDateTime::from(now - DAY);
    params.not_after = OffsetDateTime::from(now + Duration::from_secs(days * DAY.as_secs()));
}

fn read(path: &Path) -> anyhow::Result<String> {
    fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

fn write(path: &Path, contents: &str, private: bool) -> anyhow::Result<()> {
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = private;
    Ok(())
}
