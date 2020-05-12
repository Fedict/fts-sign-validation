package com.zetes.projects.bosa.signingconfigurator.service;

import com.zetes.projects.bosa.signingconfigurator.dao.ProfileSignatureParametersDao;
import com.zetes.projects.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.zetes.projects.bosa.signingconfigurator.model.ExtendedRemoteSignatureParameters;
import com.zetes.projects.bosa.signingconfigurator.model.ProfileSignatureParameters;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteBLevelParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.*;

import static eu.europa.esig.dss.enumerations.DigestAlgorithm.*;
import static javax.xml.crypto.dsig.CanonicalizationMethod.*;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("localh2")
public class SigningConfiguratorServiceTest {

    @Autowired
    private ProfileSignatureParametersDao dao;

    @Autowired
    private SigningConfiguratorService service;

    @BeforeEach
    public void clearDB() {
        dao.deleteAll();
    }

    @Test
    public void contextLoads() {
    }

    @Test
    public void throwsProfileNotFoundException() {
        // given
        ClientSignatureParameters clientParams = new ClientSignatureParameters();
        clientParams.setSigningCertificate(getSha256Certificate());
        clientParams.setSigningDate(new Date());

        // then
        ProfileNotFoundException exception = assertThrows(
                ProfileNotFoundException.class,
                () -> service.getSignatureParams("NOTFOUND", clientParams)
        );

        assertEquals("NOTFOUND not found", exception.getMessage());
    }

    @Test
    public void throwsDefaultProfileNotFoundException() {
        // given
        ClientSignatureParameters clientParams = new ClientSignatureParameters();
        clientParams.setSigningCertificate(getSha256Certificate());
        clientParams.setSigningDate(new Date());

        // then
        ProfileNotFoundException exception = assertThrows(
                ProfileNotFoundException.class,
                () -> service.getSignatureParamsDefaultProfile(clientParams)
        );

        assertEquals("Default profile not found", exception.getMessage());
    }

    @Test
    public void extensionThrowsProfileNotFoundException() {
        // given
        List<RemoteDocument> detachedContents = new ArrayList<>();

        // then
        ProfileNotFoundException exception = assertThrows(
                ProfileNotFoundException.class,
                () -> {
                    service.getExtensionParams("NOTFOUND", detachedContents);
                }
        );

        assertEquals("NOTFOUND not found", exception.getMessage());
    }

    @Test
    public void extensionThrowsDefaultProfileNotFoundException() {
        // given
        List<RemoteDocument> detachedContents = new ArrayList<>();

        // then
        ProfileNotFoundException exception = assertThrows(
                ProfileNotFoundException.class,
                () -> {
                    service.getExtensionParamsDefaultProfile(detachedContents);
                }
        );

        assertEquals("Default profile not found", exception.getMessage());
    }

    @Test
    public void saveTwoDefaultThrowsException() {
        // given
        saveProfileSignatureParameters("XADES_1", true, null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, SHA512, SignatureAlgorithm.RSA_SHA256);

        // then
        assertThrows(
                DataIntegrityViolationException.class,
                () -> saveProfileSignatureParameters("XADES_2", true, null, SignatureLevel.XAdES_BASELINE_B,
                        SignaturePackaging.ENVELOPING, DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256)
        );
    }

    @Test
    public void retrievesProfileParametersCorrectly() throws Exception {
        // given
        saveProfileSignatureParameters("XADES_B", null, null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, SHA512, SignatureAlgorithm.RSA_SHA256);
        ClientSignatureParameters clientParams = new ClientSignatureParameters();
        clientParams.setSigningCertificate(getSha256Certificate());
        clientParams.setSigningDate(new Date());

        // when
        RemoteSignatureParameters result = service.getSignatureParams("XADES_B", clientParams);

        // then
        assertNull(result.getAsicContainerType());
        assertEquals(SignatureLevel.XAdES_BASELINE_B, result.getSignatureLevel());
        assertEquals(SignaturePackaging.ENVELOPING, result.getSignaturePackaging());
        assertEquals(SignatureAlgorithm.RSA_SHA256, result.getSignatureAlgorithm());
        assertEquals(SHA512, result.getReferenceDigestAlgorithm());

        // based on SignatureAlgorithm
        assertEquals(DigestAlgorithm.SHA256, result.getDigestAlgorithm());
        assertEquals(EncryptionAlgorithm.RSA, result.getEncryptionAlgorithm());
    }

    @Test
    public void retrievesDefaultProfileParametersCorrectly() throws Exception {
        // given
        saveProfileSignatureParameters("XADES_B", true, null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, SHA512, SignatureAlgorithm.RSA_SHA256);
        ClientSignatureParameters clientParams = new ClientSignatureParameters();
        clientParams.setSigningCertificate(getSha256Certificate());
        clientParams.setSigningDate(new Date());

        // when
        RemoteSignatureParameters result = service.getSignatureParamsDefaultProfile(clientParams);

        // then
        assertNull(result.getAsicContainerType());
        assertEquals(SignatureLevel.XAdES_BASELINE_B, result.getSignatureLevel());
        assertEquals(SignaturePackaging.ENVELOPING, result.getSignaturePackaging());
        assertEquals(SignatureAlgorithm.RSA_SHA256, result.getSignatureAlgorithm());
        assertEquals(SHA512, result.getReferenceDigestAlgorithm());

        // based on SignatureAlgorithm
        assertEquals(DigestAlgorithm.SHA256, result.getDigestAlgorithm());
        assertEquals(EncryptionAlgorithm.RSA, result.getEncryptionAlgorithm());
    }

    @Test
    public void retrievesDefaultParametersCorrectly() throws Exception {
        // given
        saveProfileSignatureParameters("XADES_B", null, null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, SHA512, SignatureAlgorithm.RSA_SHA256);
        ClientSignatureParameters clientParams = new ClientSignatureParameters();
        clientParams.setSigningCertificate(getSha256Certificate());
        clientParams.setSigningDate(new Date());

        // when
        RemoteSignatureParameters result = service.getSignatureParams("XADES_B", clientParams);

        // then
        assertEquals(DigestAlgorithm.SHA256, result.getContentTimestampParameters().getDigestAlgorithm());
        assertEquals(CanonicalizationMethod.EXCLUSIVE, result.getContentTimestampParameters().getCanonicalizationMethod());
        assertEquals(DigestAlgorithm.SHA256, result.getSignatureTimestampParameters().getDigestAlgorithm());
        assertEquals(CanonicalizationMethod.EXCLUSIVE, result.getSignatureTimestampParameters().getCanonicalizationMethod());
        assertEquals(DigestAlgorithm.SHA256, result.getArchiveTimestampParameters().getDigestAlgorithm());
        assertEquals(CanonicalizationMethod.EXCLUSIVE, result.getArchiveTimestampParameters().getCanonicalizationMethod());
        assertFalse(result.isSignWithExpiredCertificate());
        assertFalse(result.isGenerateTBSWithoutCertificate());

        RemoteBLevelParameters bLevelParams = result.getBLevelParams();

        assertTrue(bLevelParams.isTrustAnchorBPPolicy());
        assertNull(bLevelParams.getPolicyId());
        assertNull(bLevelParams.getPolicyQualifier());
        assertNull(bLevelParams.getPolicyDescription());
        assertNull(bLevelParams.getPolicyDigestAlgorithm());
        assertNull(bLevelParams.getPolicyDigestValue());
        assertNull(bLevelParams.getPolicySpuri());
        assertEquals(0, bLevelParams.getCommitmentTypeIndications().size());
    }

    @Test
    public void overridesDefaultParametersCorrectly() throws Exception {
        // given
        saveProfileSignatureParameters("XADES_B", null, null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, SHA512, SignatureAlgorithm.RSA_SHA256,
                false, "id", "qualifier", "desc",
                SHA224, "digest".getBytes(), "spuri", Arrays.asList("commitment"), true, true,
                SHA1, INCLUSIVE, SHA384, EXCLUSIVE_WITH_COMMENTS, SHA512, INCLUSIVE_WITH_COMMENTS);
        ClientSignatureParameters clientParams = new ClientSignatureParameters();
        clientParams.setSigningCertificate(getSha256Certificate());
        clientParams.setSigningDate(new Date());

        // when
        RemoteSignatureParameters result = service.getSignatureParams("XADES_B", clientParams);

        // then
        assertEquals(SHA1, result.getContentTimestampParameters().getDigestAlgorithm());
        assertEquals(INCLUSIVE, result.getContentTimestampParameters().getCanonicalizationMethod());
        assertEquals(SHA384, result.getSignatureTimestampParameters().getDigestAlgorithm());
        assertEquals(EXCLUSIVE_WITH_COMMENTS, result.getSignatureTimestampParameters().getCanonicalizationMethod());
        assertEquals(SHA512, result.getArchiveTimestampParameters().getDigestAlgorithm());
        assertEquals(INCLUSIVE_WITH_COMMENTS, result.getArchiveTimestampParameters().getCanonicalizationMethod());
        assertTrue(result.isSignWithExpiredCertificate());
        assertTrue(result.isGenerateTBSWithoutCertificate());

        RemoteBLevelParameters bLevelParams = result.getBLevelParams();

        assertFalse(bLevelParams.isTrustAnchorBPPolicy());
        assertEquals("id", bLevelParams.getPolicyId());
        assertEquals("qualifier", bLevelParams.getPolicyQualifier());
        assertEquals("desc", bLevelParams.getPolicyDescription());
        assertEquals(SHA224, bLevelParams.getPolicyDigestAlgorithm());
        assertEquals("digest", new String(bLevelParams.getPolicyDigestValue()));
        assertEquals("spuri", bLevelParams.getPolicySpuri());
        assertEquals(1, bLevelParams.getCommitmentTypeIndications().size());
    }

    @Test
    public void retrievesClientParametersCorrectly() throws Exception {
        // given
        saveProfileSignatureParameters("XADES_B", null, null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, SHA512, SignatureAlgorithm.RSA_SHA256);
        ClientSignatureParameters clientParams = new ClientSignatureParameters();
        clientParams.setSigningCertificate(getSha256Certificate());
        clientParams.setCertificateChain(Arrays.asList(new RemoteCertificate(), new RemoteCertificate()));
        clientParams.setDetachedContents(Arrays.asList(new RemoteDocument(), new RemoteDocument()));
        Date signingDate = new Date();
        clientParams.setSigningDate(signingDate);
        clientParams.setPdfSignatureFieldId("fieldId");
        clientParams.setPdfSignatureFieldText("fieldText");

        clientParams.setClaimedSignerRoles(Arrays.asList("role1", "role2"));
        clientParams.setSignerLocationPostalAddress(Arrays.asList("addr1", "addr2"));
        clientParams.setSignerLocationPostalCode("1234");
        clientParams.setSignerLocationLocality("locloc");
        clientParams.setSignerLocationStateOrProvince("state");
        clientParams.setSignerLocationCountry("country");
        clientParams.setSignerLocationStreet("street");

        // when
        ExtendedRemoteSignatureParameters result = service.getSignatureParams("XADES_B", clientParams);

        // then
        assertNotNull(result.getSigningCertificate());
        assertEquals(2, result.getCertificateChain().size());
        assertEquals(2, result.getDetachedContents().size());
        assertEquals("fieldId", result.getPdfSignatureFieldId());
        assertEquals("fieldText", result.getPdfSignatureFieldText());

        RemoteBLevelParameters bLevelParams = result.getBLevelParams();

        assertEquals(signingDate, bLevelParams.getSigningDate());
        assertEquals("role1", bLevelParams.getClaimedSignerRoles().get(0));
        assertEquals("addr1", bLevelParams.getSignerLocationPostalAddress().get(0));
        assertEquals("1234", bLevelParams.getSignerLocationPostalCode());
        assertEquals("locloc", bLevelParams.getSignerLocationLocality());
        assertEquals("state", bLevelParams.getSignerLocationStateOrProvince());
        assertEquals("country", bLevelParams.getSignerLocationCountry());
        assertEquals("street", bLevelParams.getSignerLocationStreet());
    }

    @Test
    public void extensionRetrievesProfileParametersCorrectly() throws Exception {
        // given
        saveProfileSignatureParameters("XADES_B", null, null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, SHA512, SignatureAlgorithm.RSA_SHA256);
        List<RemoteDocument> detachedContents = new ArrayList<>();

        // when
        RemoteSignatureParameters result = service.getExtensionParams("XADES_B", detachedContents);

        // then
        assertNull(result.getAsicContainerType());
        assertEquals(SignatureLevel.XAdES_BASELINE_B, result.getSignatureLevel());
        assertEquals(SignaturePackaging.ENVELOPING, result.getSignaturePackaging());
        assertEquals(SignatureAlgorithm.RSA_SHA256, result.getSignatureAlgorithm());
        assertEquals(SHA512, result.getReferenceDigestAlgorithm());

        // based on SignatureAlgorithm
        assertEquals(DigestAlgorithm.SHA256, result.getDigestAlgorithm());
        assertEquals(EncryptionAlgorithm.RSA, result.getEncryptionAlgorithm());
    }

    @Test
    public void extensionRetrievesDefaultProfileParametersCorrectly() throws Exception {
        // given
        saveProfileSignatureParameters("XADES_B", true, null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, SHA512, SignatureAlgorithm.RSA_SHA256);
        List<RemoteDocument> detachedContents = new ArrayList<>();

        // when
        RemoteSignatureParameters result = service.getExtensionParamsDefaultProfile(detachedContents);

        // then
        assertNull(result.getAsicContainerType());
        assertEquals(SignatureLevel.XAdES_BASELINE_B, result.getSignatureLevel());
        assertEquals(SignaturePackaging.ENVELOPING, result.getSignaturePackaging());
        assertEquals(SignatureAlgorithm.RSA_SHA256, result.getSignatureAlgorithm());
        assertEquals(SHA512, result.getReferenceDigestAlgorithm());

        // based on SignatureAlgorithm
        assertEquals(DigestAlgorithm.SHA256, result.getDigestAlgorithm());
        assertEquals(EncryptionAlgorithm.RSA, result.getEncryptionAlgorithm());
    }

    @Test
    public void extensionRetrievesDefaultParametersCorrectly() throws Exception {
        // given
        saveProfileSignatureParameters("XADES_B", null, null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, SHA512, SignatureAlgorithm.RSA_SHA256);
        List<RemoteDocument> detachedContents = new ArrayList<>();

        // when
        RemoteSignatureParameters result = service.getExtensionParams("XADES_B", detachedContents);

        // then
        assertEquals(DigestAlgorithm.SHA256, result.getContentTimestampParameters().getDigestAlgorithm());
        assertEquals(CanonicalizationMethod.EXCLUSIVE, result.getContentTimestampParameters().getCanonicalizationMethod());
        assertEquals(DigestAlgorithm.SHA256, result.getSignatureTimestampParameters().getDigestAlgorithm());
        assertEquals(CanonicalizationMethod.EXCLUSIVE, result.getSignatureTimestampParameters().getCanonicalizationMethod());
        assertEquals(DigestAlgorithm.SHA256, result.getArchiveTimestampParameters().getDigestAlgorithm());
        assertEquals(CanonicalizationMethod.EXCLUSIVE, result.getArchiveTimestampParameters().getCanonicalizationMethod());
        assertFalse(result.isSignWithExpiredCertificate());
        assertFalse(result.isGenerateTBSWithoutCertificate());

        RemoteBLevelParameters bLevelParams = result.getBLevelParams();

        assertTrue(bLevelParams.isTrustAnchorBPPolicy());
        assertNull(bLevelParams.getPolicyId());
        assertNull(bLevelParams.getPolicyQualifier());
        assertNull(bLevelParams.getPolicyDescription());
        assertNull(bLevelParams.getPolicyDigestAlgorithm());
        assertNull(bLevelParams.getPolicyDigestValue());
        assertNull(bLevelParams.getPolicySpuri());
        assertEquals(0, bLevelParams.getCommitmentTypeIndications().size());
    }

    private RemoteCertificate getSha1Certificate() {
        return new RemoteCertificate(Base64.getDecoder().decode(
                "MIIDazCCAlOgAwIBAgIUMrYAwRoeBQtX0d0VXyej7dIzarUwDQYJKoZIhvcNAQEFBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDAzMTMxMjAwNDdaFw0yMTAzMTMxMjAwNDdaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC223qb+6tRSMmazQA2jU0HLCOkXZ5pJxTGV712LFGU+KdWCgSiRR07D1WjT9/ls9vmJELttELO0prdJ9oiIG/tEptn3/QEHPdWkRnpmiI1uDYopCPkmka0Z/qAkV3decvbWiMDeEf2zKGYoECS7xuoKNzZgz8NpsRUEiV1K9bs0QNeayPAa6242RmOjyKIkJq0BaGvR6gQ9cS1hggJsUoKuJZglh00hs/N89LPIPSL4sz/VlyMLaQpO/bT+BbE2Jpx06PksImRo1/Qzd6Qembq5BpYUPOVZLdZtp8GhLMrQ9S2/qCCw5hHLD3jeKNuAm9PM7pxBs/bMiAn0AmUIXOtAgMBAAGjUzBRMB0GA1UdDgQWBBQBbWyjzwrFEGYFN8/mjS9rhi/FRjAfBgNVHSMEGDAWgBQBbWyjzwrFEGYFN8/mjS9rhi/FRjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQBlT84jJt40ZFtDZUJmZ+cjVInRMWntsuJIsSGweK7sXqmAjLoviAMNVBGnfD0d/zpfDYIRDmeeT04uVuqYtNRSkloyaOJk5Kjd9HTKMk3TVkO5cSL8Oj6jLYJp9MT/dq2NeBroDgDneL+GhXOffFfZMlcmWHdJILIa/npIBpY6Hns4S/GSpDpktt/tWgMB72L+O7bte3FSkMNfPgH0fBz+Txpd5qZOauRqEZgwHh0EyQw/zQE8uBBV319uV9nS8zG+4SnC4uBtD7+qf5ntfH0eiHBaD28G2s0wP6W6K6gx7tmG+BL+mc81dM/cZ4tOadOgtJF3iA74LJvRRvWejsNp"
        ));
    }

    private RemoteCertificate getSha256Certificate() {
        return new RemoteCertificate(Base64.getDecoder().decode(
                "MIIDazCCAlOgAwIBAgIUG5G11AFrHfVdzy70Vk8gJUQmem0wDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDAzMTMxMjAwNTlaFw0yMTAzMTMxMjAwNTlaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCkZ0KIX5tWPssOcevS8eKUmJIKV+N7FlCytjTYb9n2qN5b97yb+k0/kgzMt/6RNwm1Y+yLkwNLsm1Y/pM25Qfl7PuVkjhOXi7hx/S2GxtGHWSn3gdpr44nuo0VebcC6Ope0LNm9KtTKGwvH3evAlpZ1sWWhmv2gOLS5A4UoYFevbxqrgxIfyVjJXAipKXfaL3vt6jKWYDrtEbv3llXKONSne67nUXBlWnzgXo/54Qdg+A38RjXtphErCXdYl23ktgIN0mVFmbg0M7CNybSecg9x10G94ntekW/u0GxVq+ZZcf+xws1dz7xFKG1zoeC28to7C8aVDDovfYi06qV9FCbAgMBAAGjUzBRMB0GA1UdDgQWBBRYvjRoOK5j1U4kGUbUetMAS6O+kTAfBgNVHSMEGDAWgBRYvjRoOK5j1U4kGUbUetMAS6O+kTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBmO0SmI/yAgLHPmzbSJ4ClktUZhAhNwiOCshs73eQuyw60MNjaIUijjasFNxs1hq0koCP5Uh9m9O6GoSuUAmIZLSKG885oB50HsOhN+sDD7mwqexiddFesTbTYEFLDmAxfyJzpF31GM2hBIxYW7Ikif9czse/xOZBjaHDYXchaA91zHfNoAXjXDIE85/ncB/KVQAd+S9YM0RlV6O1wDM2bk8LtjUJBoOnjwMIt3fI5aFjUSV0Vz+5kH6YuBD6lWhAPYUH8RGdx4g7UUkucmjbA4LjMDwehHeGr4xWMiPVJDzKLLTf19kpEwO6gQXQB/UE5v0q7hTW2B9tGfzOR9VLC"
        ));
    }

    private RemoteCertificate getSha512Certificate() {
        return new RemoteCertificate(Base64.getDecoder().decode(
                "MIIDazCCAlOgAwIBAgIUdHbFAqLPCY0kZMkedM8wau2FrEgwDQYJKoZIhvcNAQENBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDAzMTMxMjAxMTJaFw0yMTAzMTMxMjAxMTJaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDWnCx9YdRd6d7ULgJLAuqf9b7ceph/6oWk/m2cCAzYCj2sfnOhglchgJualxW/H/B6ZmRB/uYkpzl+z9Qx7GWhsyNED5LLKMWC1FvbpY/fD7OcKuFnNDOEktKwvHEkySwydFa6LFFn/b5+b8joeJwD21SYYsCzl4mgyviDWWyMfNApp8K63lKPRAKH3HDFwk5zNVWl4rDuVI06ot+oGzVBbJ7EhE5BxSHhB6AgziXW7mQ1VtckZL4y8DXSH7IXXCYtqv0YUnpJ3Lk0rk7tMzwNcrrWCqE/FmmdwDUjR2RCZfbEUdLx+pcZw+HfuJM/2Kx4NcL5nirroAXjDh35csO/AgMBAAGjUzBRMB0GA1UdDgQWBBRXBrp850Hu6J2BAqFvqYG9i7/yyzAfBgNVHSMEGDAWgBRXBrp850Hu6J2BAqFvqYG9i7/yyzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4IBAQCcbsnBcGabgm5qppg+ZFGWKOjK6IA8JvYPF5njTyCET7zUIob0i8Jzzi6Qidg1Fwlxjdl6WrYGvEGEQ90qFTWPLOWunzRZ0/X9ZLLA+2hCeB+49AWi0LMsYmmoKlWytpQs4532z8c3R9gbKGP/xpsMt8/3ku+EQZeVE1W7oX3NYg8QsB9PTWvf+Ltiw3FRtGoYn/1ptRi0+OVGsWU/ZtMv/9hq/hNshlDbK/FCj7tR0Dgp5DknGmX2yxqqhH9H08jS7/V+rQNlW/vTJqRjp7T3F4CCuunFEzCUIon+mmXnaDH70iUA+kKsvLZIMx2WZ6ivPV+ekl1lqpyz53wcmEEc"
        ));
    }

    private void saveProfileSignatureParameters(String profileId,
                                                Boolean isDefault,
                                                ASiCContainerType containerType,
                                                SignatureLevel signatureLevel,
                                                SignaturePackaging signaturePackaging,
                                                DigestAlgorithm referenceDigestAlgorithm,
                                                SignatureAlgorithm signatureAlgorithm) {
        ProfileSignatureParameters profileParams = new ProfileSignatureParameters();
        profileParams.setProfileId(profileId);
        profileParams.setIsDefault(isDefault);
        profileParams.setAsicContainerType(containerType);
        profileParams.setSignatureLevel(signatureLevel);
        profileParams.setSignaturePackaging(signaturePackaging);
        profileParams.setSignatureAlgorithm(signatureAlgorithm);
        profileParams.setReferenceDigestAlgorithm(referenceDigestAlgorithm);

        dao.save(profileParams);
    }

    private void saveProfileSignatureParameters(String profileId, Boolean isDefault,
                                                ASiCContainerType containerType,
                                                SignatureLevel signatureLevel,
                                                SignaturePackaging signaturePackaging,
                                                DigestAlgorithm referenceDigestAlgorithm,
                                                SignatureAlgorithm signatureAlgorithm,
                                                Boolean trustAnchorBPPolicy,
                                                String policyId,
                                                String policyQualifier,
                                                String policyDescription,
                                                DigestAlgorithm policyDigestAlgorithm,
                                                byte[] policyDigestValue,
                                                String policySpuri,
                                                List<String> commitmentTypeIndications,
                                                Boolean signWithExpiredCertificate,
                                                Boolean generateTBSWithoutCertificate,
                                                DigestAlgorithm contentTimestampDigestAlgorithm,
                                                String contentTimestampCanonicalizationMethod,
                                                DigestAlgorithm signatureTimestampDigestAlgorithm,
                                                String signatureTimestampCanonicalizationMethod,
                                                DigestAlgorithm archiveTimestampDigestAlgorithm,
                                                String archiveTimestampCanonicalizationMethod) {
        ProfileSignatureParameters profileParams = new ProfileSignatureParameters();
        profileParams.setProfileId(profileId);
        profileParams.setIsDefault(isDefault);
        profileParams.setAsicContainerType(containerType);
        profileParams.setSignatureLevel(signatureLevel);
        profileParams.setSignaturePackaging(signaturePackaging);
        profileParams.setSignatureAlgorithm(signatureAlgorithm);
        profileParams.setReferenceDigestAlgorithm(referenceDigestAlgorithm);

        profileParams.setTrustAnchorBPPolicy(trustAnchorBPPolicy);
        profileParams.setPolicyId(policyId);
        profileParams.setPolicyQualifier(policyQualifier);
        profileParams.setPolicyDescription(policyDescription);
        profileParams.setPolicyDigestAlgorithm(policyDigestAlgorithm);
        profileParams.setPolicyDigestValue(policyDigestValue);
        profileParams.setPolicySpuri(policySpuri);
        profileParams.setCommitmentTypeIndications(commitmentTypeIndications);
        profileParams.setSignWithExpiredCertificate(signWithExpiredCertificate);
        profileParams.setGenerateTBSWithoutCertificate(generateTBSWithoutCertificate);
        profileParams.setContentTimestampDigestAlgorithm(contentTimestampDigestAlgorithm);
        profileParams.setContentTimestampCanonicalizationMethod(contentTimestampCanonicalizationMethod);
        profileParams.setSignatureTimestampDigestAlgorithm(signatureTimestampDigestAlgorithm);
        profileParams.setSignatureTimestampCanonicalizationMethod(signatureTimestampCanonicalizationMethod);
        profileParams.setArchiveTimestampDigestAlgorithm(archiveTimestampDigestAlgorithm);
        profileParams.setArchiveTimestampCanonicalizationMethod(archiveTimestampCanonicalizationMethod);

        dao.save(profileParams);
    }

}
