import * as asn1js from "asn1js";
import type { CsrInfo } from "./types.js";

const OID_MAP: Record<string, string> = {
  "2.5.4.3": "Common Name (CN)",
  "2.5.4.6": "Country (C)",
  "2.5.4.7": "Locality (L)",
  "2.5.4.8": "State/Province (ST)",
  "2.5.4.10": "Organization (O)",
  "2.5.4.11": "Organizational Unit (OU)",
  "2.5.4.5": "Serial Number",
  "2.5.4.12": "Title",
  "1.2.840.113549.1.9.1": "Email Address",
  "1.2.840.113549.1.1.1": "RSA",
  "1.2.840.113549.1.1.5": "SHA-1 with RSA",
  "1.2.840.113549.1.1.11": "SHA-256 with RSA",
  "1.2.840.113549.1.1.12": "SHA-384 with RSA",
  "1.2.840.113549.1.1.13": "SHA-512 with RSA",
  "1.2.840.10045.2.1": "EC",
  "1.2.840.10045.4.3.2": "ECDSA with SHA-256",
  "1.2.840.10045.4.3.3": "ECDSA with SHA-384",
  "1.2.840.10045.4.3.4": "ECDSA with SHA-512",
  "1.2.840.10045.3.1.7": "P-256",
  "1.3.132.0.34": "P-384",
  "1.3.132.0.35": "P-521",
  "1.2.840.113549.1.9.14": "Extension Request",
  "1.2.840.113549.1.9.7": "Challenge Password",
  "2.5.29.17": "Subject Alternative Name",
};

function oidToName(oid: string): string {
  return OID_MAP[oid] || oid;
}

/**
 * Convert a base64url string to standard base64.
 */
function base64UrlToBase64(input: string): string {
  let b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4;
  if (pad === 2) b64 += "==";
  else if (pad === 3) b64 += "=";
  return b64;
}

/**
 * Decode a CSR (Certificate Signing Request).
 * Accepts PEM-encoded, standard base64, or base64url-encoded DER input.
 * Returns structured information about the CSR.
 */
export function decodeCsr(input: string): CsrInfo {
  const trimmed = input.trim();

  // Strip PEM headers if present, otherwise treat as raw base64/base64url
  let b64: string;
  if (trimmed.includes("-----BEGIN")) {
    b64 = trimmed
      .replace(/-----BEGIN (NEW )?CERTIFICATE REQUEST-----/g, "")
      .replace(/-----END (NEW )?CERTIFICATE REQUEST-----/g, "")
      .replace(/\s/g, "");
  } else {
    b64 = base64UrlToBase64(trimmed.replace(/\s/g, ""));
  }

  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);

  const asn1 = asn1js.fromBER(bytes.buffer);
  if (asn1.offset === -1) {
    throw new Error("Failed to parse ASN.1 structure");
  }

  const csrSeq = asn1.result as asn1js.Sequence;
  const certReqInfo = csrSeq.valueBlock.value[0] as asn1js.Sequence;
  const sigAlgoSeq = csrSeq.valueBlock.value[1] as asn1js.Sequence;
  const sigAlgoOid = (
    sigAlgoSeq.valueBlock.value[0] as asn1js.ObjectIdentifier
  ).getValue();

  // Subject
  const subjectSeq = certReqInfo.valueBlock.value[1] as asn1js.Sequence;
  const subject: Record<string, string> = {};
  if (subjectSeq.valueBlock.value) {
    for (const rdn of subjectSeq.valueBlock.value) {
      for (const atv of (rdn as asn1js.Set).valueBlock.value) {
        const atvSeq = atv as asn1js.Sequence;
        const oid = (
          atvSeq.valueBlock.value[0] as asn1js.ObjectIdentifier
        ).getValue();
        const val = atvSeq.valueBlock.value[1];
        subject[oidToName(oid)] =
          "getValue" in val
            ? String((val as asn1js.Utf8String).getValue())
            : val.valueBlock.toString();
      }
    }
  }

  // Public key info
  const pubKeyInfoSeq = certReqInfo.valueBlock.value[2] as asn1js.Sequence;
  const pkAlgoSeq = pubKeyInfoSeq.valueBlock.value[0] as asn1js.Sequence;
  const pkAlgoOid = (
    pkAlgoSeq.valueBlock.value[0] as asn1js.ObjectIdentifier
  ).getValue();
  const pkAlgoName = oidToName(pkAlgoOid);

  let publicKeySize = "";
  if (pkAlgoName === "RSA") {
    try {
      const pkBitString =
        pubKeyInfoSeq.valueBlock.value[1] as asn1js.BitString;
      const pkAsn1 = asn1js.fromBER(
        new Uint8Array(pkBitString.valueBlock.valueHexView).buffer,
      );
      if (pkAsn1.offset !== -1) {
        const modulus = (pkAsn1.result as asn1js.Sequence).valueBlock
          .value[0] as asn1js.Integer;
        const hex = Array.from(modulus.valueBlock.valueHexView)
          .map((b) => (b as number).toString(16).padStart(2, "0"))
          .join("");
        let bits = hex.length * 4;
        if (hex.startsWith("00")) bits -= 8;
        publicKeySize = `${bits} bits`;
      }
    } catch {
      publicKeySize = "Unknown";
    }
  } else if (pkAlgoName === "EC" && pkAlgoSeq.valueBlock.value.length > 1) {
    publicKeySize = oidToName(
      (pkAlgoSeq.valueBlock.value[1] as asn1js.ObjectIdentifier).getValue(),
    );
  }

  // Attributes & SANs
  const attributes: { name: string; value: string }[] = [];
  const subjectAltNames: string[] = [];

  if (certReqInfo.valueBlock.value.length > 3) {
    const attrsContext = certReqInfo.valueBlock.value[3];
    if (attrsContext?.valueBlock && "value" in attrsContext.valueBlock) {
      for (const attr of (
        attrsContext.valueBlock as { value: asn1js.AsnType[] }
      ).value) {
        const attrSeq = attr as asn1js.Sequence;
        if (attrSeq.valueBlock.value.length >= 2) {
          const attrOid = (
            attrSeq.valueBlock.value[0] as asn1js.ObjectIdentifier
          ).getValue();

          if (attrOid === "1.2.840.113549.1.9.14") {
            // Extension Request
            try {
              const extSeq = (
                attrSeq.valueBlock.value[1] as asn1js.Set
              ).valueBlock.value[0] as asn1js.Sequence;
              for (const ext of extSeq.valueBlock.value) {
                const extInner = ext as asn1js.Sequence;
                const extOid = (
                  extInner.valueBlock.value[0] as asn1js.ObjectIdentifier
                ).getValue();
                attributes.push({ name: oidToName(extOid), value: extOid });

                if (extOid === "2.5.29.17") {
                  try {
                    const sanOctet = extInner.valueBlock.value[
                      extInner.valueBlock.value.length - 1
                    ] as asn1js.OctetString;
                    const sanAsn1 = asn1js.fromBER(
                      new Uint8Array(sanOctet.valueBlock.valueHexView).buffer,
                    );
                    if (sanAsn1.offset !== -1) {
                      for (const name of (sanAsn1.result as asn1js.Sequence)
                        .valueBlock.value) {
                        const tag = (name as asn1js.BaseBlock).idBlock
                          .tagNumber;
                        const type =
                          tag === 2
                            ? "DNS"
                            : tag === 7
                              ? "IP"
                              : tag === 1
                                ? "Email"
                                : `Type ${tag}`;
                        let val = "";
                        try {
                          val =
                            "getValue" in name
                              ? String(
                                  (name as asn1js.BaseStringBlock).getValue(),
                                )
                              : new TextDecoder().decode(
                                  (name as asn1js.Primitive).valueBlock
                                    .valueHexView,
                                );
                        } catch {
                          val = "(unable to parse)";
                        }
                        subjectAltNames.push(`${type}: ${val}`);
                      }
                    }
                  } catch {
                    // SAN parsing failed
                  }
                }
              }
            } catch {
              attributes.push({
                name: oidToName(attrOid),
                value: "(unable to parse)",
              });
            }
          } else {
            attributes.push({ name: oidToName(attrOid), value: attrOid });
          }
        }
      }
    }
  }

  return {
    subject,
    publicKeyAlgorithm: pkAlgoName,
    publicKeySize,
    signatureAlgorithm: oidToName(sigAlgoOid),
    attributes,
    subjectAltNames,
  };
}
