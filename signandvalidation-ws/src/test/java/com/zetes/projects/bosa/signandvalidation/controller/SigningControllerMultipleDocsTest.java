package com.zetes.projects.bosa.signandvalidation.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zetes.projects.bosa.signandvalidation.model.DataToSignDTO;
import com.zetes.projects.bosa.signandvalidation.model.ExtendDocumentDTO;
import com.zetes.projects.bosa.signandvalidation.model.GetDataToSignMultipleDTO;
import com.zetes.projects.bosa.signandvalidation.model.SignDocumentMultipleDTO;
import com.zetes.projects.bosa.signingconfigurator.dao.ProfileSignatureParametersDao;
import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.zetes.projects.bosa.signingconfigurator.model.ProfileSignatureParameters;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

public class SigningControllerMultipleDocsTest extends SignAndValidationTestBase {

    @Autowired
    ObjectMapper mapper;

    public static final String GETDATATOSIGN_ENDPOINT = "/signing/getDataToSignMultiple";
    public static final String SIGNDOCUMENT_ENDPOINT = "/signing/signDocumentMultiple";
    public static final String EXTENDDOCUMENT_ENDPOINT = "/signing/extendDocumentMultiple";

    @BeforeAll
    public static void fillDB(ApplicationContext applicationContext) {
        ProfileSignatureParametersDao profileSigParamDao = applicationContext.getBean(ProfileSignatureParametersDao.class);
        profileSigParamDao.deleteAll();
        saveProfileSignatureParameters(profileSigParamDao, "XADES_B", ASiCContainerType.ASiC_E, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.DETACHED, null, SignatureAlgorithm.RSA_SHA256);
        saveProfileSignatureParameters(profileSigParamDao, "XADES_T", ASiCContainerType.ASiC_E, SignatureLevel.XAdES_BASELINE_T,
                SignaturePackaging.DETACHED, DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256);
    }

    @Disabled("Valid signature test") // TODO
    @Test
    public void testSigningAndExtension() throws Exception {
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(new FileInputStream("src/test/resources/user_a_rsa.p12"),
                new KeyStore.PasswordProtection("password".toCharArray()))) {

            List<DSSPrivateKeyEntry> keys = token.getKeys();
            DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

            FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
            RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(fileToSign), fileToSign.getName());
            RemoteDocument toSignDoc2 = new RemoteDocument("Hello world!".getBytes("UTF-8"), "test.bin");
            List<RemoteDocument> toSignDocuments = new ArrayList<>();
            toSignDocuments.add(toSignDocument);
            toSignDocuments.add(toSignDoc2);

            ClientSignatureParameters clientSignatureParameters = new ClientSignatureParameters();
            clientSignatureParameters.setSigningCertificate(new RemoteCertificate(dssPrivateKeyEntry.getCertificate().getCertificate().getEncoded()));
            clientSignatureParameters.setSigningDate(new Date());

            GetDataToSignMultipleDTO dataToSignDTO = new GetDataToSignMultipleDTO(toSignDocuments, "XADES_B", clientSignatureParameters);
            ToBeSignedDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + GETDATATOSIGN_ENDPOINT, dataToSignDTO, ToBeSignedDTO.class);
            assertNotNull(dataToSign);

            SignatureValue signatureValue = token.sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, dssPrivateKeyEntry);
            SignatureValueDTO signatureValueDto = new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue());

            SignDocumentMultipleDTO signDocumentDTO = new SignDocumentMultipleDTO(toSignDocuments, "XADES_B", clientSignatureParameters, signatureValueDto);
            RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + SIGNDOCUMENT_ENDPOINT, signDocumentDTO, RemoteDocument.class);

            assertNotNull(signedDocument);

            ExtendDocumentDTO extendDocumentDTO = new ExtendDocumentDTO(signedDocument, "XADES_T", toSignDocuments);
            RemoteDocument extendedDocument = this.restTemplate.postForObject(LOCALHOST + port + EXTENDDOCUMENT_ENDPOINT, extendDocumentDTO, RemoteDocument.class);

            assertNotNull(extendedDocument);

            InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
            iMD.save("target/test.asice");
        }
    }

    @Test
    public void testSigningInvalidSignature() throws Exception {
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(new FileInputStream("src/test/resources/user_a_rsa.p12"),
                new KeyStore.PasswordProtection("password".toCharArray()))) {

            List<DSSPrivateKeyEntry> keys = token.getKeys();
            DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

            FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
            RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(fileToSign), fileToSign.getName());
            RemoteDocument toSignDoc2 = new RemoteDocument("Hello world!".getBytes("UTF-8"), "test.bin");
            List<RemoteDocument> toSignDocuments = new ArrayList<>();
            toSignDocuments.add(toSignDocument);
            toSignDocuments.add(toSignDoc2);

            ClientSignatureParameters clientSignatureParameters = new ClientSignatureParameters();
            clientSignatureParameters.setSigningCertificate(new RemoteCertificate(dssPrivateKeyEntry.getCertificate().getCertificate().getEncoded()));
            clientSignatureParameters.setSigningDate(new Date());

            GetDataToSignMultipleDTO dataToSignDTO = new GetDataToSignMultipleDTO(toSignDocuments, "XADES_B", clientSignatureParameters);
            DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + GETDATATOSIGN_ENDPOINT, dataToSignDTO, DataToSignDTO.class);
            assertNotNull(dataToSign);

            SignatureValue signatureValue = token.sign(new ToBeSigned(dataToSign.getDigest()), DigestAlgorithm.SHA256, dssPrivateKeyEntry);
            SignatureValueDTO signatureValueDto = new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue());

            SignDocumentMultipleDTO signDocumentDTO = new SignDocumentMultipleDTO(toSignDocuments, "XADES_B", clientSignatureParameters, signatureValueDto);
            Map result = this.restTemplate.postForObject(LOCALHOST + port + SIGNDOCUMENT_ENDPOINT, signDocumentDTO, Map.class);

            // then
            assertEquals(BAD_REQUEST.value(), result.get("status"));
            assertEquals("Signed document did not pass validation: INDETERMINATE, NO_CERTIFICATE_CHAIN_FOUND", result.get("message"));
        }
    }

    // TODO testExtension with valid signed file
    @Test
    public void testExtensionInvalidSignature() throws Exception {
        ExtendDocumentDTO extendDocumentDTO = mapper.readValue("{\n" +
                "  \"toExtendDocument\" : {\n" +
                "    \"bytes\" : \"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\",\n" +
                "    \"digestAlgorithm\" : null,\n" +
                "    \"name\" : \"container-signed-xades-baseline-b.asice\"\n" +
                "  },\n" +
                "  \"extendProfileId\" : \"XADES_T\",\n" +
                "  \"detachedContents\" : [ {\n" +
                "    \"bytes\" : \"PGhlbGxvPndvcmxkPC9oZWxsbz4=\",\n" +
                "    \"digestAlgorithm\" : null,\n" +
                "    \"name\" : \"sample.xml\"\n" +
                "  }, {\n" +
                "    \"bytes\" : \"SGVsbG8gd29ybGQh\",\n" +
                "    \"digestAlgorithm\" : null,\n" +
                "    \"name\" : \"test.bin\"\n" +
                "  } ]\n" +
                "}", ExtendDocumentDTO.class);

        Map result = this.restTemplate.postForObject(LOCALHOST + port + EXTENDDOCUMENT_ENDPOINT, extendDocumentDTO, Map.class);

        // then
        assertEquals(BAD_REQUEST.value(), result.get("status"));
        assertEquals("Signed document did not pass validation: INDETERMINATE, NO_CERTIFICATE_CHAIN_FOUND", result.get("message"));
    }

    private static void saveProfileSignatureParameters(ProfileSignatureParametersDao dao,
                                                       String profileId,
                                                       ASiCContainerType containerType,
                                                       SignatureLevel signatureLevel,
                                                       SignaturePackaging signaturePackaging,
                                                       DigestAlgorithm referenceDigestAlgorithm,
                                                       SignatureAlgorithm... supportedSigAlgos) {
        ProfileSignatureParameters profileParams = new ProfileSignatureParameters();
        profileParams.setProfileId(profileId);
        profileParams.setAsicContainerType(containerType);
        profileParams.setSignatureLevel(signatureLevel);
        profileParams.setSignaturePackaging(signaturePackaging);
        profileParams.setSupportedSignatureAlgorithms(new HashSet<>(Arrays.asList(supportedSigAlgos)));
        profileParams.setReferenceDigestAlgorithm(referenceDigestAlgorithm);

        dao.save(profileParams);
    }

}
