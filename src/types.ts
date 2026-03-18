/** Decoded X.509 certificate information */
export interface CertInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
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

/** Decoded CSR (Certificate Signing Request) information */
export interface CsrInfo {
  subject: Record<string, string>;
  publicKeyAlgorithm: string;
  publicKeySize: string;
  signatureAlgorithm: string;
  attributes: { name: string; value: string }[];
  subjectAltNames: string[];
}
