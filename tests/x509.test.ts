import { describe, it, expect } from "vitest";
import { decodeX509 } from "../src/x509.js";

// Self-signed test certificate generated for testing purposes only
const TEST_CERT = `-----BEGIN CERTIFICATE-----
MIICpTCCAY2gAwIBAgIBATANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwlsb2Nh
bGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMzQwMTAxMDAwMDAwWjAUMRIwEAYDVQQD
Ewlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5oT/8
dhJCPDHjcL70U4I76shUwbpHOOg72Hdxn3TmHPxvO4SwhyhAuF052cAXRxbqWu3o
mQ8yxfJ2FKSlN8Q90WnV/VHrkZIp3D1s58ZhqJHljy1TeZhdfj4q6UxDFHyKuldY
c0G4iUKSNe+SkgcKmsqX2OIAY9I30fTjVHJkTUL86UQAuwrkgzMsUKkPinHdRzIl
KC6NlBLPzJUUf89rBkg/Qn7uYXwo+EDlsq7QdblqaPskjByTSqjGaWWbowwE2QIN
axlCvxEC9bAg/2T2mOcfn0TZxrzL1N1469zAkDMV8E1A/swZCUXiFvopFTZ/3Xlj
5VkikzDZkbD8NaJJAgMBAAGjAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCngh8NVjB/
kEIQsQ2DdjM8SISe9KkmOsuQz7WqdvOIKKCzTkv85U28FtQNRbe+zgkvlETPi96x
FHw3p9wXYd9uh245llTIyZxUQ+cr1ysjIxz4MkuO5OUczhqXlCZTY1HBva9xJYeN
lfwcr2bLIuzkaWS9l7EvIbPh178j4pmmFitjHrVn1MIXOdgVl+81Zcq/YWbEf+He
RhlVda5vjzkEnJC+pXMfhiNrovKyUck5yhDfBgsv/sehij1QArAf9QOMG0AHqGh1
saIjBMmw/rS0rXEwmYO0IXUVscs1T1f0nGdv2fLblsHJX7gbiBB1fOo/YjWzioKp
UKKztu7CezRH
-----END CERTIFICATE-----`;

describe("decodeX509", () => {
  it("should decode a valid PEM certificate", async () => {
    const certs = await decodeX509(TEST_CERT);
    expect(certs).toHaveLength(1);
    const cert = certs[0];
    expect(cert.subject).toContain("localhost");
    expect(cert.issuer).toContain("localhost");
    expect(cert.serialNumber).toBeTruthy();
    expect(cert.notBefore).toBeTruthy();
    expect(cert.notAfter).toBeTruthy();
    expect(cert.signatureAlgorithm).toContain("RSA");
    expect(cert.publicKeyAlgorithm).toContain("RSA");
    expect(cert.thumbprintSha1).toMatch(/^[0-9a-f:]+$/);
    expect(cert.thumbprintSha256).toMatch(/^[0-9a-f:]+$/);
    expect(cert.pem).toBe(TEST_CERT.trim());
  });

  it("should throw on invalid input", async () => {
    await expect(decodeX509("not a cert")).rejects.toThrow(
      /No valid PEM certificate blocks found/,
    );
  });

  it("should throw on empty input", async () => {
    await expect(decodeX509("")).rejects.toThrow();
  });
});
