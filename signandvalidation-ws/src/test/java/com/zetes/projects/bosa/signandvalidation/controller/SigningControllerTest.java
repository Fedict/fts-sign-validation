package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.resourcelocator.dao.SigningTypeDAO;
import com.zetes.projects.bosa.resourcelocator.model.CertificateType;
import com.zetes.projects.bosa.resourcelocator.model.SigningType;
import com.zetes.projects.bosa.resourcelocator.model.SigningTypeDTO;
import com.zetes.projects.bosa.resourcelocator.model.SigningTypeListDTO;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToSignOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.ExtendDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.SignOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static com.zetes.projects.bosa.resourcelocator.model.CertificateType.AUTHORISATION;
import static com.zetes.projects.bosa.resourcelocator.model.CertificateType.NON_REPUDIATION;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;

public class SigningControllerTest extends SignAndValidationTestBase {

    public static final String LOCALHOST = "http://localhost:";
    public static final String GETSIGNINGTYPE_ENDPOINT = "/signing/getSigningType";
    public static final String GETSIGNINGTYPES_ENDPOINT = "/signing/getSigningTypes";
    public static final String GETDATATOSIGN_ENDPOINT = "/signing/getDataToSign";
    public static final String SIGNDOCUMENT_ENDPOINT = "/signing/signDocument";
    public static final String EXTENDDOCUMENT_ENDPOINT = "/signing/extendDocument";

    @BeforeAll
    public static void fillDB(ApplicationContext applicationContext) {
        SigningTypeDAO dao = applicationContext.getBean(SigningTypeDAO.class);
        saveSigningType(dao, "auth", true, AUTHORISATION);
        saveSigningType(dao, "non-rep", true, NON_REPUDIATION);
        saveSigningType(dao, "all", true, AUTHORISATION, NON_REPUDIATION);
        saveSigningType(dao, "inactive", false, AUTHORISATION, NON_REPUDIATION);
    }

    @Test
    public void pingShouldReturnPong() throws Exception {
        // when
        String result = this.restTemplate.getForObject(LOCALHOST + port + "/signing/ping", String.class);

        // then
        assertEquals("pong", result);
    }

    @Test
    public void getSigningTypeNotFound() throws Exception {
        // when
        Map result = this.restTemplate.getForObject(LOCALHOST + port + GETSIGNINGTYPE_ENDPOINT + "/NOTFOUND", Map.class);

        // then
        assertEquals(NOT_FOUND.value(), result.get("status"));
        assertEquals("Signing type NOTFOUND not found", result.get("message"));
    }

    @Test
    public void getSigningTypeFound() throws Exception {
        // when
        SigningTypeDTO result = this.restTemplate.getForObject(LOCALHOST + port + GETSIGNINGTYPE_ENDPOINT + "/auth", SigningTypeDTO.class);

        // then
        assertNotNull(result);
        assertEquals("auth", result.getName());
    }

    @Test
    public void getSigningTypesInvalidCertificateType() throws Exception {
        // when
        Map result = this.restTemplate.getForObject(LOCALHOST + port + GETSIGNINGTYPES_ENDPOINT + "/NOTVALID", Map.class);

        // then
        assertEquals(BAD_REQUEST.value(), result.get("status"));
    }

    @Test
    public void getSigningTypesValidCertificateType() throws Exception {
        // when
        SigningTypeListDTO result = this.restTemplate.getForObject(LOCALHOST + port + GETSIGNINGTYPES_ENDPOINT + "/NON_REPUDIATION", SigningTypeListDTO.class);

        // then
        assertNotNull(result.getSigningTypes());
        assertEquals(2, result.getSigningTypes().size());
        assertEquals("non-rep", result.getSigningTypes().get(0).getName());
        assertEquals("all", result.getSigningTypes().get(1).getName());
    }

    @Test
    public void testSigningAndExtension() throws Exception {
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(new FileInputStream("src/test/resources/user_a_rsa.p12"),
                new KeyStore.PasswordProtection("password".toCharArray()))) {

            List<DSSPrivateKeyEntry> keys = token.getKeys();
            DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

            RemoteSignatureParameters parameters = new RemoteSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            parameters.setSigningCertificate(new RemoteCertificate(dssPrivateKeyEntry.getCertificate().getCertificate().getEncoded()));
            parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
            RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());
            DataToSignOneDocumentDTO dataToSignOneDocumentDTO = new DataToSignOneDocumentDTO(toSignDocument, parameters);
            ToBeSignedDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + GETDATATOSIGN_ENDPOINT, dataToSignOneDocumentDTO, ToBeSignedDTO.class);
            assertNotNull(dataToSign);

            SignatureValue signatureValue = token.sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, dssPrivateKeyEntry);
            SignOneDocumentDTO signDocument = new SignOneDocumentDTO(toSignDocument, parameters,
                    new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
            RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + SIGNDOCUMENT_ENDPOINT, signDocument, RemoteDocument.class);

            assertNotNull(signedDocument);

            parameters = new RemoteSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
            ExtendDocumentDTO extendDocumentDTO = new ExtendDocumentDTO(signedDocument, parameters);

            RemoteDocument extendedDocument = this.restTemplate.postForObject(LOCALHOST + port + EXTENDDOCUMENT_ENDPOINT, extendDocumentDTO, RemoteDocument.class);

            assertNotNull(extendedDocument);

            InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
            iMD.save("target/test.xml");
        }
    }

    @Test
    public void testSigningAndExtensionDigestDocument() throws Exception {
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(new FileInputStream("src/test/resources/user_a_rsa.p12"),
                new KeyStore.PasswordProtection("password".toCharArray()))) {

            List<DSSPrivateKeyEntry> keys = token.getKeys();
            DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

            RemoteSignatureParameters parameters = new RemoteSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            parameters.setSigningCertificate(new RemoteCertificate(dssPrivateKeyEntry.getCertificate().getCertificate().getEncoded()));
            parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
            RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.digest(DigestAlgorithm.SHA256, fileToSign), DigestAlgorithm.SHA256,
                    fileToSign.getName());
            DataToSignOneDocumentDTO dataToSignOneDocumentDTO = new DataToSignOneDocumentDTO(toSignDocument, parameters);

            ToBeSignedDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + GETDATATOSIGN_ENDPOINT, dataToSignOneDocumentDTO, ToBeSignedDTO.class);
            assertNotNull(dataToSign);

            SignatureValue signatureValue = token.sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, dssPrivateKeyEntry);
            SignOneDocumentDTO signDocument = new SignOneDocumentDTO(toSignDocument, parameters,
                    new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
            RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + SIGNDOCUMENT_ENDPOINT, signDocument, RemoteDocument.class);

            assertNotNull(signedDocument);

            parameters = new RemoteSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
            parameters.setDetachedContents(Arrays.asList(toSignDocument));
            ExtendDocumentDTO extendDocumentDTO = new ExtendDocumentDTO(signedDocument, parameters);

            RemoteDocument extendedDocument = this.restTemplate.postForObject(LOCALHOST + port + EXTENDDOCUMENT_ENDPOINT, extendDocumentDTO, RemoteDocument.class);

            assertNotNull(extendedDocument);

            InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
            iMD.save("target/test-digest.xml");
        }
    }

    private static void saveSigningType(SigningTypeDAO dao, String name, Boolean active, CertificateType... certificateTypes) {
        SigningType signingType = new SigningType();
        signingType.setName(name);
        signingType.setActive(active);
        signingType.setCertificateTypes(new HashSet<>(Arrays.asList(certificateTypes)));

        dao.save(signingType);
    }

}
