package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.*;
import com.bosa.signandvalidation.model.SignatureLevel;
import com.bosa.signingconfigurator.dao.ProfileTimestampParametersDao;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.bosa.signingconfigurator.model.ProfileSignatureParameters;
import com.bosa.signingconfigurator.model.ProfileTimestampParameters;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bosa.signandvalidation.SignAndValidationBaseTest;
import com.bosa.signandvalidation.config.ErrorStrings;
import com.bosa.signingconfigurator.dao.ProfileSignatureParametersDao;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.util.*;

import static eu.europa.esig.dss.enumerations.DigestAlgorithm.SHA256;
import static eu.europa.esig.dss.enumerations.Indication.TOTAL_PASSED;
import static eu.europa.esig.dss.enumerations.TimestampContainerForm.PDF;
import static javax.xml.crypto.dsig.Transform.ENVELOPED;
import static org.junit.jupiter.api.Assertions.*;

public class DoubleTestCheckSignatureLevel extends SignAndValidationBaseTest implements ErrorStrings {

    @Autowired
    ObjectMapper mapper;

    public static final String GETDATATOSIGN_ENDPOINT = "/signing/getDataToSign";
    public static final String SIGNDOCUMENT_ENDPOINT = "/signing/signDocument";
    public static final String VALIDATE_ENDPOINT = "/validation/validateSignature";

    @BeforeAll
    public static void fillDB(ApplicationContext applicationContext) {
        ProfileSignatureParametersDao profileSigParamDao = applicationContext.getBean(ProfileSignatureParametersDao.class);
        profileSigParamDao.deleteAll();
        saveProfileSignatureParameters(profileSigParamDao, "XADES_B", null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPED, null, SHA256);
        saveProfileSignatureParameters(profileSigParamDao, "XADES_T", null, SignatureLevel.XAdES_BASELINE_T,
                SignaturePackaging.ENVELOPED, null, SHA256);
        saveProfileSignatureParameters(profileSigParamDao, "XADES_LT", null, SignatureLevel.XAdES_BASELINE_LT,
                SignaturePackaging.ENVELOPED, null, SHA256);
        saveProfileSignatureParameters(profileSigParamDao, "XADES_LTA", null, SignatureLevel.XAdES_BASELINE_LTA,
                SignaturePackaging.ENVELOPED, null, SHA256);
        saveProfileSignatureParameters(profileSigParamDao, "CADES_B", ASiCContainerType.ASiC_S, SignatureLevel.CAdES_BASELINE_B,
                SignaturePackaging.DETACHED, null, SHA256);
        saveProfileSignatureParameters(profileSigParamDao, "CADES_T", ASiCContainerType.ASiC_S, SignatureLevel.CAdES_BASELINE_T,
                SignaturePackaging.DETACHED, null, SHA256);
        saveProfileSignatureParameters(profileSigParamDao, "CADES_LT", ASiCContainerType.ASiC_S, SignatureLevel.CAdES_BASELINE_LT,
                SignaturePackaging.DETACHED, null, SHA256);
        saveProfileSignatureParameters(profileSigParamDao, "CADES_LTA", ASiCContainerType.ASiC_S, SignatureLevel.CAdES_BASELINE_LTA,
                SignaturePackaging.DETACHED, null, SHA256);
        saveProfileSignatureParameters(profileSigParamDao, "PADES_B", null, SignatureLevel.PAdES_BASELINE_B,
                SignaturePackaging.ENVELOPED, null, SHA256);
        saveProfileSignatureParameters(profileSigParamDao, "PADES_T", null, SignatureLevel.PAdES_BASELINE_T,
                SignaturePackaging.ENVELOPED, null, SHA256);
        saveProfileSignatureParameters(profileSigParamDao, "PADES_LT", null, SignatureLevel.PAdES_BASELINE_LT,
                SignaturePackaging.ENVELOPED, null, SHA256);
        saveProfileSignatureParameters(profileSigParamDao, "PADES_LTA", null, SignatureLevel.PAdES_BASELINE_LTA,
                SignaturePackaging.ENVELOPED, null, SHA256);

        ProfileTimestampParametersDao timestampParamDao = applicationContext.getBean(ProfileTimestampParametersDao.class);
        timestampParamDao.deleteAll();
        saveProfileTimestampParameters(timestampParamDao, "PROFILE_1", SHA256, ENVELOPED, PDF);
    }

    @Test
    public void testXadesSigningLevel() throws Exception {
        checkSignature("sample.xml", "XADES_B", SignatureLevel.XAdES_BASELINE_B);
        checkSignature("sample.xml", "XADES_T", SignatureLevel.XAdES_BASELINE_T);
        checkSignature("sample.xml", "XADES_LT", SignatureLevel.XAdES_BASELINE_LT);
        checkSignature("sample.xml", "XADES_LTA", SignatureLevel.XAdES_BASELINE_LTA);

        checkSignature("sample.xml", "XADES_B", SignatureLevel.XAdES_BASELINE_LTA, true);
    }

        @Test
        public void testCadesSigningLevel() throws Exception {
            checkSignature("sample.xml", "CADES_B", SignatureLevel.CAdES_BASELINE_B);
            checkSignature("sample.xml", "CADES_T", SignatureLevel.CAdES_BASELINE_T);
            checkSignature("sample.xml", "CADES_LT", SignatureLevel.CAdES_BASELINE_LT);
            checkSignature("sample.xml", "CADES_LTA", SignatureLevel.CAdES_BASELINE_LTA);

            checkSignature("sample.xml", "CADES_LTA", SignatureLevel.CAdES_BASELINE_B, true);
        }

        @Test
        public void testPadesSigningLevel() throws Exception {
            checkSignature("sample.pdf", "PADES_B", SignatureLevel.PAdES_BASELINE_B);
            checkSignature("sample.pdf", "PADES_T", SignatureLevel.PAdES_BASELINE_T);
            checkSignature("sample.pdf", "PADES_LT", SignatureLevel.PAdES_BASELINE_LT);
            checkSignature("sample.pdf", "PADES_LTA", SignatureLevel.PAdES_BASELINE_LTA);

            checkSignature("sample.pdf", "PADES_T", SignatureLevel.PAdES_BASELINE_B, true);
        }

    private void checkSignature(String fileName, String profileId, SignatureLevel level) throws IOException {
        checkSignature(fileName, profileId, level, false);
    }

    private void checkSignature(String fileName, String profileId, SignatureLevel level, boolean expectError) throws IOException {
        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );

        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters params = getClientSignatureParameters(dssPrivateKeyEntry);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/" + fileName));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

        // get data to sign
        GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, profileId, params, "ID");
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + GETDATATOSIGN_ENDPOINT, dataToSignDTO, DataToSignDTO.class);
        assertNotNull(dataToSign);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        params.setSigningDate(dataToSign.getSigningDate());
        SignDocumentDTO signDocumentDTO = new SignDocumentDTO(toSignDocument, profileId, params, signatureValue.getValue(), null, "ID");
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + SIGNDOCUMENT_ENDPOINT, signDocumentDTO, RemoteDocument.class);
        assertNotNull(signedDocument);

        DataToValidateDTO toValidate = new DataToValidateDTO(signedDocument);
        toValidate.setLevel(level);

        // check signature level is as requested
        if (expectError) {
            Map result = this.restTemplate.postForObject(LOCALHOST + port + VALIDATE_ENDPOINT, toValidate, Map.class);

            assertNotNull(result);
            assertTrue(((String)result.get("message")).contains(INVALID_SIGNATURE_LEVEL));
        } else {
            SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + VALIDATE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

            assertNotNull(result);
            assertEquals(TOTAL_PASSED, result.getIndication());
            assertNull(result.getSubIndicationLabel());
        }
    }

    private ClientSignatureParameters getClientSignatureParameters(DSSPrivateKeyEntry dssPrivateKeyEntry) {
        List<RemoteCertificate> chain = new ArrayList<>();
        for (CertificateToken token : dssPrivateKeyEntry.getCertificateChain()) {
            chain.add(new RemoteCertificate(token.getEncoded()));
        }

        ClientSignatureParameters clientSignatureParameters = new ClientSignatureParameters();
        clientSignatureParameters.setSigningCertificate(new RemoteCertificate(dssPrivateKeyEntry.getCertificate().getEncoded()));
        clientSignatureParameters.setCertificateChain(chain);
        clientSignatureParameters.setSigningDate(new Date());
        return clientSignatureParameters;
    }

    private static void saveProfileSignatureParameters(ProfileSignatureParametersDao dao,
                                                       String profileId,
                                                       ASiCContainerType containerType,
                                                       SignatureLevel signatureLevel,
                                                       SignaturePackaging signaturePackaging,
                                                       DigestAlgorithm referenceDigestAlgorithm,
                                                       DigestAlgorithm digestAlgorithm) {
        ProfileSignatureParameters profileParams = new ProfileSignatureParameters();
        profileParams.setProfileId(profileId);
        profileParams.setAsicContainerType(containerType);
        profileParams.setSignatureLevel(signatureLevel.toDSS());
        profileParams.setSignaturePackaging(signaturePackaging);
        profileParams.setDigestAlgorithm(digestAlgorithm);
        profileParams.setReferenceDigestAlgorithm(referenceDigestAlgorithm);
        profileParams.setTspServer("http://tsa.belgium.be/connect");

        dao.save(profileParams);
    }

    private static void saveProfileTimestampParameters(ProfileTimestampParametersDao dao,
                                                       String profileId,
                                                       DigestAlgorithm digestAlgorithm,
                                                       String canonicalizationMethod,
                                                       TimestampContainerForm containerForm) {
        ProfileTimestampParameters profileParams = new ProfileTimestampParameters();
        profileParams.setProfileId(profileId);
        profileParams.setDigestAlgorithm(digestAlgorithm);
        profileParams.setCanonicalizationMethod(canonicalizationMethod);
        profileParams.setContainerForm(containerForm);
        profileParams.setTspServer("http://tsa.belgium.be/connect");

        dao.save(profileParams);
    }
}
