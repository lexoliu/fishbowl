//! The gateway's own certificate authority.
//!
//! Auditing TLS means terminating it, so the gateway mints a leaf for every server name
//! the sandbox asks for. The authority is generated on first start inside the sandbox and
//! trusted by the sandbox's own trust store; it never leaves the VM and never signs
//! anything the host relies on.

use std::{path::Path, sync::Arc};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio::fs;

use crate::error::{GatewayError, Result};

/// Common name the sandbox sees in its trust store.
const AUTHORITY_NAME: &str = "fishbowl audit gateway";

/// A certificate authority that mints one leaf per intercepted server name.
#[derive(Debug)]
pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    certificate: CertificateDer<'static>,
}

impl CertificateAuthority {
    /// Loads the authority from disk, generating it the first time the sandbox boots.
    ///
    /// The private key sits next to the certificate with the `.key` suffix and is written
    /// before the certificate, so the certificate's presence is what tells the entrypoint
    /// the authority is ready to install.
    ///
    /// # Errors
    /// Fails when the key material cannot be generated, read or written.
    pub async fn load_or_create(certificate_path: &Path) -> Result<Self> {
        let key_path = certificate_path.with_extension("key");
        let (key_pem, certificate_pem) = match fs::read_to_string(&key_path).await {
            Ok(key_pem) => {
                let certificate_pem = read(certificate_path).await?;
                (key_pem, certificate_pem)
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                let (key_pem, certificate_pem) = Self::generate()?;
                write(&key_path, &key_pem).await?;
                write(certificate_path, &certificate_pem).await?;
                (key_pem, certificate_pem)
            }
            Err(source) => {
                return Err(GatewayError::File {
                    path: key_path,
                    source,
                });
            }
        };

        let key_pair = KeyPair::from_pem(&key_pem)?;
        let certificate =
            CertificateDer::from_pem_slice(certificate_pem.as_bytes()).map_err(|_| {
                GatewayError::File {
                    path: certificate_path.to_path_buf(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "the gateway CA certificate is not valid PEM",
                    ),
                }
            })?;
        let issuer = Issuer::from_ca_cert_der(&certificate, key_pair)?;
        Ok(Self {
            issuer,
            certificate,
        })
    }

    fn generate() -> Result<(String, String)> {
        let key_pair = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, AUTHORITY_NAME);
        params.distinguished_name = name;
        let certificate = params.self_signed(&key_pair)?;
        Ok((key_pair.serialize_pem(), certificate.pem()))
    }

    /// Mints a short chain for `server_name`, valid for the sandbox's trust store only.
    ///
    /// # Errors
    /// Fails when the leaf cannot be generated or its key is not one rustls can sign with.
    pub fn leaf_for(&self, server_name: &str) -> Result<CertifiedKey> {
        let key_pair = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![server_name.to_owned()])?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, server_name);
        params.distinguished_name = name;
        let leaf = params.signed_by(&key_pair, &self.issuer)?;

        let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(
            key_pair.serialize_der().into(),
        ))?;
        Ok(CertifiedKey::new(
            vec![leaf.der().clone(), self.certificate.clone()],
            signing_key,
        ))
    }
}

async fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path)
        .await
        .map_err(|source| GatewayError::File {
            path: path.to_path_buf(),
            source,
        })
}

async fn write(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents)
        .await
        .map_err(|source| GatewayError::File {
            path: path.to_path_buf(),
            source,
        })
}

/// Resolves the leaf presented to one intercepted connection.
///
/// A sample that dials a bare address sends no SNI, so the resolver falls back to the
/// original destination recovered from netfilter rather than failing the handshake and
/// losing the record of what the sample tried to reach.
#[derive(Debug)]
pub struct InterceptResolver {
    authority: Arc<CertificateAuthority>,
    fallback_name: String,
}

impl InterceptResolver {
    /// Builds a resolver for a single connection aimed at `fallback_name`.
    #[must_use]
    pub fn new(authority: Arc<CertificateAuthority>, fallback_name: String) -> Self {
        Self {
            authority,
            fallback_name,
        }
    }
}

impl ResolvesServerCert for InterceptResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello
            .server_name()
            .unwrap_or(self.fallback_name.as_str());
        match self.authority.leaf_for(server_name) {
            Ok(certified) => Some(Arc::new(certified)),
            Err(error) => {
                tracing::error!(%error, server_name, "failed to mint an interception leaf");
                None
            }
        }
    }
}
