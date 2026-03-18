# cert-tools

Decode X.509 certificates and CSRs (Certificate Signing Requests) from PEM format in Node.js.

## Install

```bash
npm install @kejun/cert-tools
```

## Usage

### Decode X.509 Certificate

```ts
import { decodeX509 } from "@kejun/cert-tools";

const pem = `-----BEGIN CERTIFICATE-----
MIICpTCCAY2gAwIBAgIB...
-----END CERTIFICATE-----`;

const certs = await decodeX509(pem);
console.log(certs[0].subject);       // "CN=localhost"
console.log(certs[0].issuer);
console.log(certs[0].isValid);       // true/false
console.log(certs[0].thumbprintSha256);
```

### Decode CSR

```ts
import { decodeCsr } from "@kejun/cert-tools";

const pem = `-----BEGIN CERTIFICATE REQUEST-----
MIICgDCCAWgCAQAwOzEZ...
-----END CERTIFICATE REQUEST-----`;

const info = decodeCsr(pem);
console.log(info.subject);           // { "Common Name (CN)": "example.com", ... }
console.log(info.publicKeyAlgorithm); // "RSA"
console.log(info.publicKeySize);      // "2048 bits"
console.log(info.subjectAltNames);    // ["DNS: example.com", ...]
```

## API

### `decodeX509(pem: string): Promise<CertInfo[]>`

Parses one or more PEM-encoded X.509 certificates. Returns an array of `CertInfo` objects with:

`subject`, `issuer`, `serialNumber`, `notBefore`, `notAfter`, `isValid`, `signatureAlgorithm`, `publicKeyAlgorithm`, `publicKeySize`, `thumbprintSha1`, `thumbprintSha256`, `extensions`, `subjectAltNames`, `pem`

### `decodeCsr(pem: string): CsrInfo`

Parses a PEM-encoded CSR. Returns a `CsrInfo` object with:

`subject`, `publicKeyAlgorithm`, `publicKeySize`, `signatureAlgorithm`, `attributes`, `subjectAltNames`

## License

MIT