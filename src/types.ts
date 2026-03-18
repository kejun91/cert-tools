/** Decoded X.509 certificate information */
export interface CertInfo {
  subject: string;
  /** Subject fields parsed into key-value pairs, e.g. { "commonName": "example.com" } */
  subjectParsed: Record<string, string>;
  issuer: string;
  /** Issuer fields parsed into key-value pairs */
  issuerParsed: Record<string, string>;
  serialNumber: string;
  /** Certificate version, e.g. 3 for v3 */
  version: number;
  notBefore: string;
  notAfter: string;
  isValid: boolean;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  publicKeySize: string;
  thumbprintSha1: string;
  thumbprintSha256: string;
  extensions: { name: string; critical: boolean; oid: string }[];
  subjectAltNames: string[];
  pem: string;
}

/**
 * Decoded CSR (Certificate Signing Request) information.
 * Accepts PEM-encoded or raw base64/base64url-encoded DER input.
 */
export interface CsrInfo {
  subject: Record<string, string>;
  publicKeyAlgorithm: string;
  publicKeySize: string;
  signatureAlgorithm: string;
  attributes: { name: string; value: string }[];
  subjectAltNames: string[];
}
