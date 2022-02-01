package com.zetes.projects.bosa.signandvalidation.service;

import eu.europa.esig.dss.ws.dto.RemoteCertificate;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.*;

public class CertInfoTest {
    @Test
    public void testGetters() throws Exception {
        CertInfo ci = new CertInfo(getTomTestCertificate());
        assertEquals("Tom", ci.getGivenName());
        assertEquals("Test", ci.getSurname());
        assertEquals("73040102749", ci.getSerialNumber());
    }

    private static RemoteCertificate tomTestCert = null;

    static RemoteCertificate getTomTestCertificate() {
        if (null == tomTestCert)
        tomTestCert =  new RemoteCertificate(Base64.getDecoder().decode(
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
        return tomTestCert;
    }
}
