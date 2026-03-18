import { describe, it, expect } from "vitest";
import { decodeCsr } from "../src/csr.js";

// Test CSR generated for testing purposes only (RSA 2048, CN=test.example.com)
const TEST_CSR = `-----BEGIN CERTIFICATE REQUEST-----
MIICgDCCAWgCAQAwOzEZMBcGA1UEAxMQdGVzdC5leGFtcGxlLmNvbTERMA8GA1UE
ChMIVGVzdCBPcmcxCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAsWTBfGLorz8Q18f6S0B3EKuDKvl3XMa7shkUGqTPXuSqeXMr+3UA
j/GMDg76cgGk9MetxZM9QxghTzFpO7d0rjddJx1MkKTRYpz+CZrznhkRiv20n0X1
GvtLeodRbf9S8Na4nejIN/clA2FwL6Dc0BW93rgZpJO97Cie3zBmRgl4H6KcD/DI
z+xikkPYsM9LvcPe8NP2P9pf+7iCPvJpmh84vjxExMo+YP1zVN5bQYl2+ZBjSfO4
BXuthUiCd+tKS7yFEFfRBh2nzjAaBEVpQ7VZRu9fIp2SYGkBago0Vko5/FJCbGjM
xgjvCLB/TeikbO6tlqkVWpoSPDVuVIAnQQIDAQABoAAwDQYJKoZIhvcNAQELBQAD
ggEBACGq3GKNX6ff5unSiSz/et6z/7Cta9Wr/fprfsjZtmMZFI89a0tsW/HRemQu
q+rV53B5uiVUrXhGaMm0qfl9J4Dzl4CqIZ25R+cQwMKH2GLuqC2MW62oYtss0DAQ
ptlOKRUkZBvN0CNHLZCAssIdha5ykrrpF0Q2+yiyHeUDNSNHINT4X6TEgFGr1C65
Lm7tRVqnFRAgGOaQT6dQlgWCpNRIRqEdsIGN1vVgOR+bSveDnlcRyhipBCQk7IOL
Ahf/xmmoGn0A1OB7YKfk+Sl555uNJqxqH+vNZZaavnPknTIoYEalMs5q/J3pPysQ
R6erdTLneMkzxlnJnsi0gcS301k=
-----END CERTIFICATE REQUEST-----`;

describe("decodeCsr", () => {
  it("should decode a valid PEM CSR", () => {
    const info = decodeCsr(TEST_CSR);
    expect(info.subject["Common Name (CN)"]).toBe("test.example.com");
    expect(info.signatureAlgorithm).toContain("RSA");
    expect(info.publicKeyAlgorithm).toBe("RSA");
    expect(info.publicKeySize).toMatch(/bits/);
  });

  it("should throw on invalid input", () => {
    expect(() => decodeCsr("not a csr")).toThrow();
  });
});
