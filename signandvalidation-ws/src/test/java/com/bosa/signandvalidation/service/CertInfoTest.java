package com.bosa.signandvalidation.service;

import eu.europa.esig.dss.ws.dto.RemoteCertificate;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.*;

public class CertInfoTest {
    @Test
    public void testGetters() {
        CertInfo ci = new CertInfo(getTomTestCertificate());
        assertEquals("Tom", ci.getGivenName());
        assertEquals("Test", ci.getSurname());
        assertEquals("73040102749", ci.getSerialNumber());
    }

    @Test
    public void testGettersNOK() {
        CertInfo ci = new CertInfo(getOtherTestCertificate());
        assertEquals("?", ci.getGivenName());
    }

    @Test()
    public void testInvalidCert() {
        try {
            new CertInfo(new RemoteCertificate(new byte[1]));
            fail("Exception exptected");
        } catch(RuntimeException ignored) {
        }
    }

    static RemoteCertificate getTomTestCertificate() {
        return new RemoteCertificate(Base64.getDecoder().decode(
                    "MIIEezCCBACgAwIBAgIRANar/0/BA2zhfogU3c2l9VgwCgYIKoZIzj0EAwMwWDEL" +
                            "MAkGA1UEBhMCQkUxGzAZBgNVBAoMEkJlbGdpYW4gR292ZXJubWVudDEbMBkGA1UE" +
                            "AwwSVGVzdFNpZ24gQ2l0aXplbkNBMQ8wDQYDVQQFEwYyMDIwMDEwHhcNMjAwMTIy" +
                            "MTQzMTM0WhcNMzIwMTA4MTQzMTM0WjBTMQswCQYDVQQGEwJCRTENMAsGA1UEBAwE" +
                            "VGVzdDEMMAoGA1UEKgwDVG9tMRQwEgYDVQQFEws3MzA0MDEwMjc0OTERMA8GA1UE" +
                            "AwwIVG9tIFRlc3QwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATPJn02bi2fQhorEFk9" +
                            "fmXhhvUIhu3yR724JnEiWvS0fP73HdvzIlnp2FxxsNKN+VHg4Y/kD3O7CrQ92OCo" +
                            "+ybHWZJ9gN50+ZyFjcHNh1zd86YNotJkXaDw0UkvfMGtdiSjggKRMIICjTAOBgNV" +
                            "HQ8BAf8EBAMCBkAwEwYDVR0lBAwwCgYIKwYBBQUHAwQwHQYDVR0OBBYEFBiGa6/M" +
                            "pKTK4kUQ4sb4NoQGnN9tMB8GA1UdIwQYMBaAFDYX+xTfoQ34PmyRvZTBWkP9yZFg" +
                            "MD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9ob21lLnNjYXJsZXQuYmUvc3RoL2Np" +
                            "dGl6ZW4yMDIwMDEuY3JsMEgGCCsGAQUFBwEBBDwwOjA4BggrBgEFBQcwAoYsaHR0" +
                            "cDovL2hvbWUuc2NhcmxldC5iZS9zdGgvY2l0aXplbjIwMjAwMS5jcnQwggEpBgNV" +
                            "HSAEggEgMIIBHDCCARgGB2A4DQYBh2gwggELMDQGCCsGAQUFBwIBFihodHRwczov" +
                            "L3JlcG9zaXRvcnkuZWlkcGtpLmJlbGdpdW0uYmUvZWlkMIHSBggrBgEFBQcCAjCB" +
                            "xQyBwkdlYnJ1aWsgb25kZXJ3b3JwZW4gYWFuIGFhbnNwcmFrZWxpamtoZWlkc2Jl" +
                            "cGVya2luZ2VuLCB6aWUgQ1BTIC0gVXNhZ2Ugc291bWlzIMODwqAgZGVzIGxpbWl0" +
                            "YXRpb25zIGRlIHJlc3BvbnNhYmlsaXTDg8KpLCB2b2lyIENQUyAtIFZlcndlbmR1" +
                            "bmcgdW50ZXJsaWVndCBIYWZ0dW5nc2Jlc2NocsODwqRua3VuZ2VuLCBnZW3Dg8Kk" +
                            "c3MgQ1BTMHAGCCsGAQUFBwEDBGQwYjAIBgYEAI5GAQEwCAYGBACORgEEMBMGBgQA" +
                            "jkYBBjAJBgcEAI5GAQYBMDcGBgQAjkYBBTAtMCsWJWh0dHBzOi8vcmVwb3NpdG9y" +
                            "eS5wa2kuYmVsZ2l1bS5iZS9laWQTAmVuMAoGCCqGSM49BAMDA2kAMGYCMQDKhf5V" +
                            "IjYQ7sxz0WkR6NSwQDX6okEuEXM2EGNlQoBwqcEDvfTfa9pEbX5GcKf7o/4CMQDP" +
                            "NpeKR1KKs5BEmZSEouxmaCxPjUJXpCmKL9jFjxX/L3ZyEe8r3VznYtxo8/4WEkQ="
            ));
    }
    static RemoteCertificate getOtherTestCertificate() {
        return new RemoteCertificate(Base64.getDecoder().decode(
                "MIIDrjCCApigAwIBAgIBATALBgkqhkiG9w0BAQUwHjEcMAkGA1UEBhMCUlUwDwYD" +
                "VQQDHggAVABlAHMAdDAeFw0xOTAxMzEyMzAwMDBaFw0yMjAxMzEyMzAwMDBaMB4x" +
                "HDAJBgNVBAYTAlJVMA8GA1UEAx4IAFQAZQBzAHQwggEiMA0GCSqGSIb3DQEBAQUA" +
                "A4IBDwAwggEKAoIBAQCxNvI55vRgHWagaeuBOiXJNjlZ/KVAWnT4NbR1ZoiOYfb/" +
                "HRjyPJiW3TXsnG6JJlVvl9SAeqq3rj3GtVIu2QFn9mSQh0k3C3HHD5ZWEAqg0U2p" +
                "Y0hGGqyyfUk5H4Hh2Y5JY13fsCf/MEV/SdUpk6vWTtI8RKEwcQNZvexbxgYqMxBQ" +
                "WyPt640X4XGBXXJq6gfqN2rMkO3FNw04g2NQklx/CrZEhcKAyKBs1NYkgSKWK+Zm" +
                "4TPhHB2R+J5qi8mw52/nNS90nBs890DppKLErDeW7efXYal2v0UcPkfXirVes895" +
                "eEswCxwXWw9f7K3vyvEOZ15hHfmjWCWNGQd+4Qj5AgMBAAGjgfowgfcwEgYDVR0T" +
                "AQH/BAgwBgEB/wIBAzALBgNVHQ8EBAMCAAYwYwYDVR0lBFwwWgYEVR0lAAYIKwYB" +
                "BQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYBBQUHAwQGCCsGAQUFBwMIBggr" +
                "BgEFBQcDCQYKKwYBBAGCNwoDAQYKKwYBBAGCNwoDBDAXBgkrBgEEAYI3FAIECgwI" +
                "Y2VydFR5cGUwIwYJKwYBBAGCNxUCBBYEFAEBAQEBAQEBAQEBAQEBAQEBAQEBMBwG" +
                "CSsGAQQBgjcVBwQPMA0GBSkBAQEBAgEKAgEUMBMGCSsGAQQBgjcVAQQGAgQAFAAK" +
                "MAsGCSqGSIb3DQEBBQOCAQEAe29m/flolfIOtNsbP925Gm1NGeH2mmQQJHCid9iX" +
                "ZhmaVw5C2C5zqM2fxY2NwpmNyTZ98AKAgQrimQrWWtj8Evmx6pv5sc8MmLcybgs3" +
                "cDrxBqk0JZohPPz9kJxhHISdBqRLRx6HG2sK8b5iTNOKBLmdaSyf45DWgdvh/bXM" +
                "ZKp4usu4htNyQ1A9q3ScFKaln6oNs1vYJFyyZ20cumexi/v8VZzq/1yyAGBQ6Fv8" +
                "CbH2UXFu//tjGEV9QVkPgs38VcRQUJZ/gJazMCKmkjMvU/ViCL8BRbyZSBQ6yGkC" +
                "E8Jjcdi1xj2bKbp4FjefF4sJxuzj3Nk5jLOndZF3czA94Q=="
        ));
    }
}
