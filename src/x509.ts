import * as x509 from "@peculiar/x509";
import * as asn1js from "asn1js";
import type { CertInfo } from "./types.js";

// Use globalThis.crypto (available in modern browsers & Node 19+).
// For older Node versions, the consumer can call `x509.cryptoProvider.set(...)` themselves.
if (typeof globalThis.crypto !== "undefined") {
  x509.cryptoProvider.set(globalThis.crypto);
}

function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(":");
}

function getAlgorithmName(algo: { name?: string; hash?: string | { name: string }; namedCurve?: string }): string {
  const name = algo.name || "Unknown";
  if (algo.hash) {
    const hashName = typeof algo.hash === "string" ? algo.hash : algo.hash.name;
    return `${name} with ${hashName}`;
  }
  if (algo.namedCurve) return `${name} (${algo.namedCurve})`;
  return name;
}

const EXTENSION_NAMES: Record<string, string> = {
  "2.5.29.14": "Subject Key Identifier",
  "2.5.29.15": "Key Usage",
  "2.5.29.17": "Subject Alternative Name",
  "2.5.29.19": "Basic Constraints",
  "2.5.29.31": "CRL Distribution Points",
  "2.5.29.32": "Certificate Policies",
  "2.5.29.35": "Authority Key Identifier",
  "2.5.29.37": "Extended Key Usage",
  "1.3.6.1.5.5.7.1.1": "Authority Information Access",
  "1.3.6.1.5.5.7.1.3": "Qualified Certificate Statements",
  "1.3.6.1.4.1.11129.2.4.2": "CT Precertificate SCTs",
};

function getExtensionName(oid: string): string {
  return EXTENSION_NAMES[oid] || oid;
}

/** OID-to-friendly-name mapping for distinguished name attributes */
const DN_OID_NAMES: Record<string, string> = {
  "2.5.4.3": "commonName",
  "2.5.4.6": "countryName",
  "2.5.4.7": "localityName",
  "2.5.4.8": "stateOrProvinceName",
  "2.5.4.10": "organizationName",
  "2.5.4.11": "organizationalUnitName",
  "2.5.4.5": "serialNumber",
  "2.5.4.12": "title",
  "1.2.840.113549.1.9.1": "emailAddress",
};

/**
 * Parse an X.500 distinguished name string (e.g. "CN=foo, O=bar") into a
 * Record using friendly attribute names.
 */
function parseDN(dn: string): Record<string, string> {
  const result: Record<string, string> = {};
  // Split on ", " but not within quoted values
  const parts = dn.split(/,\s*/);
  for (const part of parts) {
    const eqIdx = part.indexOf("=");
    if (eqIdx === -1) continue;
    const key = part.slice(0, eqIdx).trim();
    const value = part.slice(eqIdx + 1).trim();
    // Map short names to long names
    const longName =
      key === "CN" ? "commonName" :
      key === "O" ? "organizationName" :
      key === "OU" ? "organizationalUnitName" :
      key === "C" ? "countryName" :
      key === "L" ? "localityName" :
      key === "ST" ? "stateOrProvinceName" :
      key === "E" || key === "emailAddress" ? "emailAddress" :
      key === "SERIALNUMBER" ? "serialNumber" :
      key;
    result[longName] = value;
  }
  return result;
}

/**
 * Extract the certificate version from raw DER data.
 * Version is in TBSCertificate → first element (context tag 0) → INTEGER.
 * Returns 1, 2, or 3. Defaults to 1 if the explicit version tag is absent (per RFC 5280).
 */
function extractVersion(rawData: ArrayBuffer): number {
  try {
    const asn1 = asn1js.fromBER(rawData);
    const tbsCert = (asn1.result as asn1js.Sequence).valueBlock.value[0] as asn1js.Sequence;
    const first = tbsCert.valueBlock.value[0];
    // Explicit context tag [0] wraps the version INTEGER
    if (first.idBlock.tagNumber === 0 && "value" in first.valueBlock) {
      const versionInt = (first.valueBlock as { value: asn1js.AsnType[] }).value[0] as asn1js.Integer;
      return (versionInt.valueBlock as { valueDec: number }).valueDec + 1;
    }
  } catch {
    // fall through
  }
  return 1; // default per RFC 5280
}

/**
 * Decode one or more PEM-encoded X.509 certificates.
 * Returns an array of CertInfo objects (one per certificate found).
 */
export async function decodeX509(pem: string): Promise<CertInfo[]> {
  const pemBlocks = pem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
  );
  if (!pemBlocks || pemBlocks.length === 0) {
    throw new Error(
      "No valid PEM certificate blocks found. Input must contain -----BEGIN CERTIFICATE----- / -----END CERTIFICATE----- blocks.",
    );
  }

  const results: CertInfo[] = [];

  for (const block of pemBlocks) {
    const cert = new x509.X509Certificate(block);
    const now = new Date();

    let publicKeySize = "";
    try {
      const keyAlgo = cert.publicKey.algorithm as { modulusLength?: number; namedCurve?: string };
      if (keyAlgo.modulusLength) publicKeySize = `${keyAlgo.modulusLength} bits`;
      else if (keyAlgo.namedCurve) publicKeySize = keyAlgo.namedCurve;
    } catch {
      publicKeySize = "Unknown";
    }

    const sha1 = await cert.getThumbprint("SHA-1");
    const sha256 = await cert.getThumbprint("SHA-256");

    let subjectAltNames: string[] = [];
    try {
      const sanExt = cert.getExtension("2.5.29.17");
      if (sanExt) {
        const san = new x509.SubjectAlternativeNameExtension(sanExt.rawData);
        if (san.names?.items) {
          for (const altName of san.names.items) {
            subjectAltNames.push(`${altName.type}: ${altName.value}`);
          }
        }
      }
    } catch {
      // SAN parsing failed – not critical
    }

    results.push({
      subject: cert.subject,
      subjectParsed: parseDN(cert.subject),
      issuer: cert.issuer,
      issuerParsed: parseDN(cert.issuer),
      serialNumber: cert.serialNumber,
      version: extractVersion(cert.rawData),
      notBefore: cert.notBefore.toISOString(),
      notAfter: cert.notAfter.toISOString(),
      isValid: now >= cert.notBefore && now <= cert.notAfter,
      signatureAlgorithm: getAlgorithmName(cert.signatureAlgorithm as Parameters<typeof getAlgorithmName>[0]),
      publicKeyAlgorithm: getAlgorithmName(cert.publicKey.algorithm as Parameters<typeof getAlgorithmName>[0]),
      publicKeySize,
      thumbprintSha1: bufferToHex(sha1),
      thumbprintSha256: bufferToHex(sha256),
      extensions: cert.extensions.map((ext) => ({
        name: getExtensionName(ext.type),
        critical: ext.critical,
        oid: ext.type,
      })),
      subjectAltNames,
      pem: block,
    });
  }

  return results;
}
