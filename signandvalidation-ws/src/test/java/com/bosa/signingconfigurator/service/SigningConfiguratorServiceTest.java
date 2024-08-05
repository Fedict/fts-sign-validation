package com.bosa.signingconfigurator.service;

import com.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.bosa.signingconfigurator.model.ProfileSignatureParameters;
import com.bosa.signingconfigurator.dao.ProfileSignatureParametersDao;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteBLevelParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.*;

import static eu.europa.esig.dss.enumerations.DigestAlgorithm.*;
import static eu.europa.esig.dss.enumerations.TimestampContainerForm.*;
import static javax.xml.crypto.dsig.CanonicalizationMethod.*;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Import(FileCacheDataLoader.class)
@ActiveProfiles("localh2")
public class SigningConfiguratorServiceTest {

    @MockBean
    private OnlineTSPSource tspSource;

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
        clientParams.setSigningCertificate(getRsaCertificate());
        clientParams.setSigningDate(new Date());

        // then
        ProfileNotFoundException exception = assertThrows(
                ProfileNotFoundException.class,
                () -> service.getSignatureParams(null, clientParams, null)
        );

        assertEquals("Default profile not found", exception.getMessage());
    }

    @Test
    public void throwsDefaultProfileNotFoundException() {
        // given
        ClientSignatureParameters clientParams = new ClientSignatureParameters();
        clientParams.setSigningCertificate(getRsaCertificate());
        clientParams.setSigningDate(new Date());

        // then
        ProfileNotFoundException exception = assertThrows(
                ProfileNotFoundException.class,
                () -> service.getSignatureParams(null, clientParams, null)
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
                    service.getExtensionParams(null, detachedContents);
                }
        );

        assertEquals("Default profile not found", exception.getMessage());
    }

    @Test
    public void extensionThrowsDefaultProfileNotFoundException() {
        // given
        List<RemoteDocument> detachedContents = new ArrayList<>();

        // then
        ProfileNotFoundException exception = assertThrows(
                ProfileNotFoundException.class,
                () -> {
                    service.getExtensionParams(null, detachedContents);
                }
        );

        assertEquals("Default profile not found", exception.getMessage());
    }

    @Test
    public void retrievesProfileParametersCorrectly() throws Exception {
        // given
        saveProfileSignatureParameters("XADES_B", null, null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, SHA512, SHA256, null, "tspServer");
        ClientSignatureParameters clientParams = new ClientSignatureParameters();
        clientParams.setSigningCertificate(getRsaCertificate());
        clientParams.setSigningDate(new Date());

        // when

        RemoteSignatureParameters result = service.getSignatureParams(service.findProfileParamsById("XADES_B"), clientParams, null);

        // then
        assertNull(result.getAsicContainerType());
        assertEquals(SignatureLevel.XAdES_BASELINE_B, result.getSignatureLevel());
        assertEquals(SignaturePackaging.ENVELOPING, result.getSignaturePackaging());
        assertEquals(SHA512, result.getReferenceDigestAlgorithm());

        // based on SignatureAlgorithm
        assertEquals(DigestAlgorithm.SHA256, result.getDigestAlgorithm());
        assertEquals(EncryptionAlgorithm.RSA, result.getEncryptionAlgorithm());
    }

    @Test
    public void retrievesDefaultProfileParametersCorrectly() throws Exception {
        // given
        saveProfileSignatureParameters("XADES_B", true, null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, SHA512, SHA256, null, "tspServer");
        ClientSignatureParameters clientParams = new ClientSignatureParameters();
        clientParams.setSigningCertificate(getRsaCertificate());
        clientParams.setSigningDate(new Date());

        // when
        RemoteSignatureParameters result = service.getSignatureParams(null, clientParams, null);

        // then
        assertNull(result.getAsicContainerType());
        assertEquals(SignatureLevel.XAdES_BASELINE_B, result.getSignatureLevel());
        assertEquals(SignaturePackaging.ENVELOPING, result.getSignaturePackaging());
        assertEquals(SHA512, result.getReferenceDigestAlgorithm());

        // based on SignatureAlgorithm
        assertEquals(DigestAlgorithm.SHA256, result.getDigestAlgorithm());
        assertEquals(EncryptionAlgorithm.RSA, result.getEncryptionAlgorithm());
    }

    @Test
    public void retrievesSignatureAlgorithmCorrectly() throws Exception {
        // given
        saveProfileSignatureParameters("XADES_B", true, null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, SHA512, SHA384, null, "tspServer");
        ClientSignatureParameters clientParams = new ClientSignatureParameters();
        clientParams.setSigningCertificate(getEcCertificate());
        clientParams.setSigningDate(new Date());

        // when
        RemoteSignatureParameters result = service.getSignatureParams(null, clientParams, null);

        // then
        // based on SignatureAlgorithm
        assertEquals(SHA384, result.getDigestAlgorithm());
        assertEquals(EncryptionAlgorithm.ECDSA, result.getEncryptionAlgorithm());
    }

    @Test
    public void retrievesDefaultParametersCorrectly() throws Exception {
        // given
        saveProfileSignatureParameters("XADES_B", null, null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, SHA512, SHA256, null, "tspServer");
        ClientSignatureParameters clientParams = new ClientSignatureParameters();
        clientParams.setSigningCertificate(getRsaCertificate());
        clientParams.setSigningDate(new Date());

        // when
        RemoteSignatureParameters result = service.getSignatureParams(service.findProfileParamsById("XADES_B"), clientParams, null);

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
                SignaturePackaging.ENVELOPING, SHA512, SHA256, null,
                false, "id", ObjectIdentifierQualifier.OID_AS_URI, "desc",
                SHA224, "digest".getBytes(), "spuri", Arrays.asList(CommitmentTypeEnum.ProofOfOrigin), true, true,
                SHA1, INCLUSIVE, PDF, SHA384, EXCLUSIVE_WITH_COMMENTS, ASiC_E, SHA512, INCLUSIVE_WITH_COMMENTS, ASiC_S, "tspServer");
        ClientSignatureParameters clientParams = new ClientSignatureParameters();
        clientParams.setSigningCertificate(getRsaCertificate());
        clientParams.setSigningDate(new Date());

        // when
        RemoteSignatureParameters result = service.getSignatureParams(service.findProfileParamsById("XADES_B"), clientParams, null);

        // then
        assertEquals(SHA1, result.getContentTimestampParameters().getDigestAlgorithm());
        assertEquals(INCLUSIVE, result.getContentTimestampParameters().getCanonicalizationMethod());
        assertEquals(PDF, result.getContentTimestampParameters().getTimestampContainerForm());
        assertEquals(SHA384, result.getSignatureTimestampParameters().getDigestAlgorithm());
        assertEquals(EXCLUSIVE_WITH_COMMENTS, result.getSignatureTimestampParameters().getCanonicalizationMethod());
        assertEquals(ASiC_E, result.getSignatureTimestampParameters().getTimestampContainerForm());
        assertEquals(SHA512, result.getArchiveTimestampParameters().getDigestAlgorithm());
        assertEquals(INCLUSIVE_WITH_COMMENTS, result.getArchiveTimestampParameters().getCanonicalizationMethod());
        assertEquals(ASiC_S, result.getArchiveTimestampParameters().getTimestampContainerForm());
        assertTrue(result.isSignWithExpiredCertificate());
        assertTrue(result.isGenerateTBSWithoutCertificate());

        RemoteBLevelParameters bLevelParams = result.getBLevelParams();

        assertFalse(bLevelParams.isTrustAnchorBPPolicy());
        assertEquals("id", bLevelParams.getPolicyId());
        assert(ObjectIdentifierQualifier.OID_AS_URI.equals(bLevelParams.getPolicyQualifier()));
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
                SignaturePackaging.ENVELOPING, SHA512, SHA256, null, "tspServer");
        ClientSignatureParameters clientParams = new ClientSignatureParameters();
        clientParams.setSigningCertificate(getRsaCertificate());
        clientParams.setCertificateChain(Arrays.asList(new RemoteCertificate(), new RemoteCertificate()));
        clientParams.setDetachedContents(Arrays.asList(new RemoteDocument(), new RemoteDocument()));
        Date signingDate = new Date();
        clientParams.setSigningDate(signingDate);

        clientParams.setClaimedSignerRoles(Arrays.asList("role1", "role2"));
        clientParams.setSignerLocationPostalAddress(Arrays.asList("addr1", "addr2"));
        clientParams.setSignerLocationPostalCode("1234");
        clientParams.setSignerLocationLocality("locloc");
        clientParams.setSignerLocationStateOrProvince("state");
        clientParams.setSignerLocationCountry("country");
        clientParams.setSignerLocationStreet("street");

        // when
        RemoteSignatureParameters result = service.getSignatureParams(service.findProfileParamsById("XADES_B"), clientParams, null);

        // then
        assertNotNull(result.getSigningCertificate());
        assertEquals(2, result.getCertificateChain().size());
        assertEquals(2, result.getDetachedContents().size());

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
                SignaturePackaging.ENVELOPING, SHA512, SHA256, null, "tspServer");
        List<RemoteDocument> detachedContents = new ArrayList<>();

        // when
        RemoteSignatureParameters result = service.getExtensionParams(service.findProfileParamsById("XADES_B"), detachedContents);

        // then
        assertNull(result.getAsicContainerType());
        assertEquals(SignatureLevel.XAdES_BASELINE_B, result.getSignatureLevel());
        assertEquals(SignaturePackaging.ENVELOPING, result.getSignaturePackaging());
        //assertEquals(SignatureAlgorithm.RSA_SHA256, getSignatureAlgorithm(result)); Not needed since extension does not sign
        assertEquals(SHA512, result.getReferenceDigestAlgorithm());

        // based on SignatureAlgorithm
        assertEquals(DigestAlgorithm.SHA256, result.getDigestAlgorithm());
        //assertEquals(EncryptionAlgorithm.RSA, result.getEncryptionAlgorithm()); Not needed since extension does not sign
    }

    @Test
    public void extensionRetrievesDefaultProfileParametersCorrectly() throws Exception {
        // given
        saveProfileSignatureParameters("XADES_B", true, null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, SHA512, SHA256, null, "tspServer");
        List<RemoteDocument> detachedContents = new ArrayList<>();

        // when
        RemoteSignatureParameters result = service.getExtensionParams(null, detachedContents);

        // then
        assertNull(result.getAsicContainerType());
        assertEquals(SignatureLevel.XAdES_BASELINE_B, result.getSignatureLevel());
        assertEquals(SignaturePackaging.ENVELOPING, result.getSignaturePackaging());
        //assertEquals(SignatureAlgorithm.RSA_SHA256, getSignatureAlgorithm(result)); Not needed since extension does not sign
        assertEquals(SHA512, result.getReferenceDigestAlgorithm());

        // based on SignatureAlgorithm
        assertEquals(DigestAlgorithm.SHA256, result.getDigestAlgorithm());
        //assertEquals(EncryptionAlgorithm.RSA, result.getEncryptionAlgorithm()); Not needed since extension does not sign
    }

    @Test
    public void extensionRetrievesDefaultParametersCorrectly() throws Exception {
        // given
        saveProfileSignatureParameters("XADES_B", null, null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, SHA512, SHA256, null, "tspServer");
        List<RemoteDocument> detachedContents = new ArrayList<>();

        // when
        RemoteSignatureParameters result = service.getExtensionParams(service.findProfileParamsById("XADES_B"), detachedContents);

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

    private RemoteCertificate getRsaCertificate() {
        return new RemoteCertificate(Base64.getDecoder().decode(
                "MIIDazCCAlOgAwIBAgIUG5G11AFrHfVdzy70Vk8gJUQmem0wDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDAzMTMxMjAwNTlaFw0yMTAzMTMxMjAwNTlaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCkZ0KIX5tWPssOcevS8eKUmJIKV+N7FlCytjTYb9n2qN5b97yb+k0/kgzMt/6RNwm1Y+yLkwNLsm1Y/pM25Qfl7PuVkjhOXi7hx/S2GxtGHWSn3gdpr44nuo0VebcC6Ope0LNm9KtTKGwvH3evAlpZ1sWWhmv2gOLS5A4UoYFevbxqrgxIfyVjJXAipKXfaL3vt6jKWYDrtEbv3llXKONSne67nUXBlWnzgXo/54Qdg+A38RjXtphErCXdYl23ktgIN0mVFmbg0M7CNybSecg9x10G94ntekW/u0GxVq+ZZcf+xws1dz7xFKG1zoeC28to7C8aVDDovfYi06qV9FCbAgMBAAGjUzBRMB0GA1UdDgQWBBRYvjRoOK5j1U4kGUbUetMAS6O+kTAfBgNVHSMEGDAWgBRYvjRoOK5j1U4kGUbUetMAS6O+kTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBmO0SmI/yAgLHPmzbSJ4ClktUZhAhNwiOCshs73eQuyw60MNjaIUijjasFNxs1hq0koCP5Uh9m9O6GoSuUAmIZLSKG885oB50HsOhN+sDD7mwqexiddFesTbTYEFLDmAxfyJzpF31GM2hBIxYW7Ikif9czse/xOZBjaHDYXchaA91zHfNoAXjXDIE85/ncB/KVQAd+S9YM0RlV6O1wDM2bk8LtjUJBoOnjwMIt3fI5aFjUSV0Vz+5kH6YuBD6lWhAPYUH8RGdx4g7UUkucmjbA4LjMDwehHeGr4xWMiPVJDzKLLTf19kpEwO6gQXQB/UE5v0q7hTW2B9tGfzOR9VLC"
        ));
    }

    private RemoteCertificate getEcCertificate() {
        return new RemoteCertificate(Base64.getDecoder().decode(
                "MIIB3zCCAYWgAwIBAgIUcIwmbWb1vgfXsH6A1cyY22Li420wCgYIKoZIzj0EAwIw" +
                        "RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu" +
                        "dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDA2MjQxMzMxMDhaFw0yMTA2MjQx" +
                        "MzMxMDhaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD" +
                        "VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjO" +
                        "PQMBBwNCAAT8FD5vJrQyqIziQoGe88aBHJ/x6BeLPP6lyUrz5u1Msevp2lCMYgxa" +
                        "P9ufhTHb1J9gsFnHP21ddQLSaE1a7oGPo1MwUTAdBgNVHQ4EFgQUjSr/bdxi9B+d" +
                        "gjXZ70MdtWdT1ZYwHwYDVR0jBBgwFoAUjSr/bdxi9B+dgjXZ70MdtWdT1ZYwDwYD" +
                        "VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA4MxREFjCkeMDlXnoSfoC" +
                        "3+HlZXuOYE+ulUgWpDhtK7ICIGGAqaJKBCoeSN1rh95DOgWu2Ron8rc/x8vtXKRG" +
                        "0Hba"
        ));
    }

    private void saveProfileSignatureParameters(String profileId,
                                                Boolean isDefault,
                                                ASiCContainerType containerType,
                                                SignatureLevel signatureLevel,
                                                SignaturePackaging signaturePackaging,
                                                DigestAlgorithm referenceDigestAlgorithm,
                                                DigestAlgorithm digestAlgorithm,
                                                MaskGenerationFunction maskGenerationFunction,
                                                String tspServer) {
        ProfileSignatureParameters profileParams = new ProfileSignatureParameters();
        profileParams.setProfileId(profileId);
        profileParams.setIsDefault(isDefault);
        profileParams.setAsicContainerType(containerType);
        profileParams.setSignatureLevel(signatureLevel);
        profileParams.setSignaturePackaging(signaturePackaging);
        profileParams.setDigestAlgorithm(digestAlgorithm);
        profileParams.setMaskGenerationFunction(maskGenerationFunction);
        profileParams.setReferenceDigestAlgorithm(referenceDigestAlgorithm);

        profileParams.setTspServer(tspServer);

        dao.save(profileParams);
    }

    private void saveProfileSignatureParameters(String profileId, Boolean isDefault,
                                                ASiCContainerType containerType,
                                                SignatureLevel signatureLevel,
                                                SignaturePackaging signaturePackaging,
                                                DigestAlgorithm referenceDigestAlgorithm,
                                                DigestAlgorithm digestAlgorithm,
                                                MaskGenerationFunction maskGenerationFunction,
                                                Boolean trustAnchorBPPolicy,
                                                String policyId,
                                                ObjectIdentifierQualifier policyQualifier,
                                                String policyDescription,
                                                DigestAlgorithm policyDigestAlgorithm,
                                                byte[] policyDigestValue,
                                                String policySpuri,
                                                List<CommitmentTypeEnum> commitmentTypeIndications,
                                                Boolean signWithExpiredCertificate,
                                                Boolean generateTBSWithoutCertificate,
                                                DigestAlgorithm contentTimestampDigestAlgorithm,
                                                String contentTimestampCanonicalizationMethod,
                                                TimestampContainerForm contentTimestampContainerForm,
                                                DigestAlgorithm signatureTimestampDigestAlgorithm,
                                                String signatureTimestampCanonicalizationMethod,
                                                TimestampContainerForm signatureTimestampContainerForm,
                                                DigestAlgorithm archiveTimestampDigestAlgorithm,
                                                String archiveTimestampCanonicalizationMethod,
                                                TimestampContainerForm archiveTimestampContainerForm,
                                                String tspServer) {
        ProfileSignatureParameters profileParams = new ProfileSignatureParameters();
        profileParams.setProfileId(profileId);
        profileParams.setIsDefault(isDefault);
        profileParams.setAsicContainerType(containerType);
        profileParams.setSignatureLevel(signatureLevel);
        profileParams.setSignaturePackaging(signaturePackaging);
        profileParams.setDigestAlgorithm(digestAlgorithm);
        profileParams.setMaskGenerationFunction(maskGenerationFunction);
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
        profileParams.setContentTimestampContainerForm(contentTimestampContainerForm);
        profileParams.setSignatureTimestampDigestAlgorithm(signatureTimestampDigestAlgorithm);
        profileParams.setSignatureTimestampCanonicalizationMethod(signatureTimestampCanonicalizationMethod);
        profileParams.setSignatureTimestampContainerForm(signatureTimestampContainerForm);
        profileParams.setArchiveTimestampDigestAlgorithm(archiveTimestampDigestAlgorithm);
        profileParams.setArchiveTimestampCanonicalizationMethod(archiveTimestampCanonicalizationMethod);
        profileParams.setArchiveTimestampContainerForm(archiveTimestampContainerForm);

        profileParams.setTspServer(tspServer);

        dao.save(profileParams);
    }

}
