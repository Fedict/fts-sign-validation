package com.zetes.projects.bosa.signandvalidation.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zetes.projects.bosa.resourcelocator.dao.SigningTypeDAO;
import com.zetes.projects.bosa.resourcelocator.model.CertificateType;
import com.zetes.projects.bosa.resourcelocator.model.SigningType;
import com.zetes.projects.bosa.resourcelocator.model.SigningTypeDTO;
import com.zetes.projects.bosa.resourcelocator.model.SigningTypeListDTO;
import com.zetes.projects.bosa.signandvalidation.SignAndValidationTestBase;
import com.zetes.projects.bosa.signandvalidation.model.DataToSignDTO;
import com.zetes.projects.bosa.signandvalidation.model.ExtendDocumentDTO;
import com.zetes.projects.bosa.signandvalidation.model.GetDataToSignDTO;
import com.zetes.projects.bosa.signandvalidation.model.SignDocumentDTO;
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
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
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

import static com.zetes.projects.bosa.resourcelocator.model.CertificateType.AUTHORISATION;
import static com.zetes.projects.bosa.resourcelocator.model.CertificateType.NON_REPUDIATION;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;

public class SigningControllerTest extends SignAndValidationTestBase {

    @Autowired
    ObjectMapper mapper;

    public static final String GETSIGNINGTYPE_ENDPOINT = "/signing/getSigningType";
    public static final String GETSIGNINGTYPES_ENDPOINT = "/signing/getSigningTypes";
    public static final String GETDATATOSIGN_ENDPOINT = "/signing/getDataToSign";
    public static final String SIGNDOCUMENT_ENDPOINT = "/signing/signDocument";
    public static final String EXTENDDOCUMENT_ENDPOINT = "/signing/extendDocument";

    @BeforeAll
    public static void fillDB(ApplicationContext applicationContext) {
        SigningTypeDAO signingTypeDao = applicationContext.getBean(SigningTypeDAO.class);
        signingTypeDao.deleteAll();
        saveSigningType(signingTypeDao, "auth", true, AUTHORISATION);
        saveSigningType(signingTypeDao, "non-rep", true, NON_REPUDIATION);
        saveSigningType(signingTypeDao, "all", true, AUTHORISATION, NON_REPUDIATION);
        saveSigningType(signingTypeDao, "inactive", false, AUTHORISATION, NON_REPUDIATION);

        ProfileSignatureParametersDao profileSigParamDao = applicationContext.getBean(ProfileSignatureParametersDao.class);
        profileSigParamDao.deleteAll();
        saveProfileSignatureParameters(profileSigParamDao, "XADES_1", null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, null, SignatureAlgorithm.RSA_SHA256);
        saveProfileSignatureParameters(profileSigParamDao, "XADES_2", null, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.DETACHED, DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256);
        saveProfileSignatureParameters(profileSigParamDao, "XADES_T", null, SignatureLevel.XAdES_BASELINE_T,
                SignaturePackaging.ENVELOPING, DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256);
        saveProfileSignatureParameters(profileSigParamDao, "PADES_1", null, SignatureLevel.PAdES_BASELINE_B,
                SignaturePackaging.ENVELOPING, DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256);
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

    @Disabled("Valid signature test") // TODO
    @Test
    public void testSigningAndExtension() throws Exception {
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(new FileInputStream("src/test/resources/user_a_rsa.p12"),
                new KeyStore.PasswordProtection("password".toCharArray()))) {

            List<DSSPrivateKeyEntry> keys = token.getKeys();
            DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

            FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
            RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

            ClientSignatureParameters clientSignatureParameters = new ClientSignatureParameters();
            clientSignatureParameters.setSigningCertificate(new RemoteCertificate(dssPrivateKeyEntry.getCertificate().getCertificate().getEncoded()));
            clientSignatureParameters.setSigningDate(new Date());
            GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, "XADES_1", clientSignatureParameters);
            ToBeSignedDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + GETDATATOSIGN_ENDPOINT, dataToSignDTO, ToBeSignedDTO.class);
            assertNotNull(dataToSign);

            SignatureValue signatureValue = token.sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, dssPrivateKeyEntry);
            SignDocumentDTO signDocumentDTO = new SignDocumentDTO(toSignDocument, "XADES_1", clientSignatureParameters, signatureValue.getValue());
            RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + SIGNDOCUMENT_ENDPOINT, signDocumentDTO, RemoteDocument.class);

            assertNotNull(signedDocument);

            ExtendDocumentDTO extendDocumentDTO = new ExtendDocumentDTO(signedDocument, "XADES_T", null);
            RemoteDocument extendedDocument = this.restTemplate.postForObject(LOCALHOST + port + EXTENDDOCUMENT_ENDPOINT, extendDocumentDTO, RemoteDocument.class);

            assertNotNull(extendedDocument);

            InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
            iMD.save("target/test.xml");
        }
    }

    @Test
    public void testSigningInvalidSignature() throws Exception {
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(new FileInputStream("src/test/resources/user_a_rsa.p12"),
                new KeyStore.PasswordProtection("password".toCharArray()))) {

            List<DSSPrivateKeyEntry> keys = token.getKeys();
            DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

            FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
            RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

            ClientSignatureParameters clientSignatureParameters = new ClientSignatureParameters();
            clientSignatureParameters.setSigningCertificate(new RemoteCertificate(dssPrivateKeyEntry.getCertificate().getCertificate().getEncoded()));
            clientSignatureParameters.setSigningDate(new Date());
            GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, "XADES_1", clientSignatureParameters);
            DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + GETDATATOSIGN_ENDPOINT, dataToSignDTO, DataToSignDTO.class);
            assertNotNull(dataToSign);

            SignatureValue signatureValue = token.sign(new ToBeSigned(dataToSign.getDigest()), DigestAlgorithm.SHA256, dssPrivateKeyEntry);
            SignDocumentDTO signDocumentDTO = new SignDocumentDTO(toSignDocument, "XADES_1", clientSignatureParameters, signatureValue.getValue());
            Map result = this.restTemplate.postForObject(LOCALHOST + port + SIGNDOCUMENT_ENDPOINT, signDocumentDTO, Map.class);

            // then
            assertEquals(BAD_REQUEST.value(), result.get("status"));
            assertEquals("Signed document did not pass validation: INDETERMINATE, NO_CERTIFICATE_CHAIN_FOUND", result.get("message"));
        }
    }

    @Test
    public void testSigningPdfInvalidSignature() throws Exception {
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(new FileInputStream("src/test/resources/user_a_rsa.p12"),
                new KeyStore.PasswordProtection("password".toCharArray()))) {

            List<DSSPrivateKeyEntry> keys = token.getKeys();
            DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

            FileDocument fileToSign = new FileDocument(new File("src/test/resources/doc.pdf"));
            RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

            ClientSignatureParameters clientSignatureParameters = new ClientSignatureParameters();
            clientSignatureParameters.setSigningCertificate(new RemoteCertificate(dssPrivateKeyEntry.getCertificate().getCertificate().getEncoded()));
            clientSignatureParameters.setSigningDate(new Date());
            clientSignatureParameters.setPdfSignatureFieldId("Signature1");
            clientSignatureParameters.setPdfSignatureFieldText("Sig text");
            GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, "PADES_1", clientSignatureParameters);
            DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + GETDATATOSIGN_ENDPOINT, dataToSignDTO, DataToSignDTO.class);
            assertNotNull(dataToSign);

            SignatureValue signatureValue = token.sign(new ToBeSigned(dataToSign.getDigest()), DigestAlgorithm.SHA256, dssPrivateKeyEntry);
            SignDocumentDTO signDocumentDTO = new SignDocumentDTO(toSignDocument, "PADES_1", clientSignatureParameters, signatureValue.getValue());

            Map result = this.restTemplate.postForObject(LOCALHOST + port + SIGNDOCUMENT_ENDPOINT, signDocumentDTO, Map.class);

            // then
            assertEquals(BAD_REQUEST.value(), result.get("status"));
            assertEquals("Signed document did not pass validation: INDETERMINATE, NO_CERTIFICATE_CHAIN_FOUND", result.get("message"));
        }
    }

    @Disabled("Valid signature test") // TODO
    @Test
    public void testSigningAndExtensionDigestDocument() throws Exception {
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(new FileInputStream("src/test/resources/user_a_rsa.p12"),
                new KeyStore.PasswordProtection("password".toCharArray()))) {

            List<DSSPrivateKeyEntry> keys = token.getKeys();
            DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

            FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
            RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.digest(DigestAlgorithm.SHA256, fileToSign), DigestAlgorithm.SHA256,
                    fileToSign.getName());
            ClientSignatureParameters clientSignatureParameters = new ClientSignatureParameters();
            clientSignatureParameters.setSigningCertificate(new RemoteCertificate(dssPrivateKeyEntry.getCertificate().getCertificate().getEncoded()));
            clientSignatureParameters.setSigningDate(new Date());
            GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, "XADES_2", clientSignatureParameters);

            ToBeSignedDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + GETDATATOSIGN_ENDPOINT, dataToSignDTO, ToBeSignedDTO.class);
            assertNotNull(dataToSign);

            SignatureValue signatureValue = token.sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, dssPrivateKeyEntry);
            SignDocumentDTO signDocumentDTO = new SignDocumentDTO(toSignDocument, "XADES_2", clientSignatureParameters, signatureValue.getValue());
            RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + SIGNDOCUMENT_ENDPOINT, signDocumentDTO, RemoteDocument.class);

            assertNotNull(signedDocument);

            ExtendDocumentDTO extendDocumentDTO = new ExtendDocumentDTO(signedDocument, "XADES_T", null);

            RemoteDocument extendedDocument = this.restTemplate.postForObject(LOCALHOST + port + EXTENDDOCUMENT_ENDPOINT, extendDocumentDTO, RemoteDocument.class);

            assertNotNull(extendedDocument);

            InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
            iMD.save("target/test-digest.xml");
        }
    }

    @Test
    public void testSigningDigestDocumentInvalidSignature() throws Exception {
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(new FileInputStream("src/test/resources/user_a_rsa.p12"),
                new KeyStore.PasswordProtection("password".toCharArray()))) {

            List<DSSPrivateKeyEntry> keys = token.getKeys();
            DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

            FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
            RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.digest(DigestAlgorithm.SHA256, fileToSign), DigestAlgorithm.SHA256,
                    fileToSign.getName());
            ClientSignatureParameters clientSignatureParameters = new ClientSignatureParameters();
            clientSignatureParameters.setSigningCertificate(new RemoteCertificate(dssPrivateKeyEntry.getCertificate().getCertificate().getEncoded()));
            clientSignatureParameters.setSigningDate(new Date());
            GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, "XADES_2", clientSignatureParameters);

            DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + GETDATATOSIGN_ENDPOINT, dataToSignDTO, DataToSignDTO.class);
            assertNotNull(dataToSign);

            SignatureValue signatureValue = token.sign(new ToBeSigned(dataToSign.getDigest()), DigestAlgorithm.SHA256, dssPrivateKeyEntry);
            SignDocumentDTO signDocumentDTO = new SignDocumentDTO(toSignDocument, "XADES_2", clientSignatureParameters, signatureValue.getValue());
            Map result = this.restTemplate.postForObject(LOCALHOST + port + SIGNDOCUMENT_ENDPOINT, signDocumentDTO, Map.class);

            // then
            assertEquals(BAD_REQUEST.value(), result.get("status"));
            assertEquals("Signed document did not pass validation: INDETERMINATE, NO_CERTIFICATE_CHAIN_FOUND", result.get("message"));
        }
    }

    // TODO testExtension with valid signed file
    @Test
    public void testExtensionInvalidSignature() throws Exception {
        com.zetes.projects.bosa.signandvalidation.model.ExtendDocumentDTO extendDocumentDTO = mapper.readValue("{\n" +
                "  \"toExtendDocument\" : {\n" +
                "    \"bytes\" : \"PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyIgSWQ9ImlkLWUwNTAwMTY2YmQ4YjI4Njc0OGE2MTAwODQ1MjA0ZmZkIj48ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnL1RSLzIwMDEvUkVDLXhtbC1jMTRuLTIwMDEwMzE1Ii8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz48ZHM6UmVmZXJlbmNlIElkPSJyLWlkLWUwNTAwMTY2YmQ4YjI4Njc0OGE2MTAwODQ1MjA0ZmZkLTEiIFR5cGU9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNPYmplY3QiIFVSST0iI28taWQtZTA1MDAxNjZiZDhiMjg2NzQ4YTYxMDA4NDUyMDRmZmQtMSI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNiYXNlNjQiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkczpEaWdlc3RWYWx1ZT56ZGhjVEpzYlE2cVg1ZThJa2RseUp6Qms5YkJ1VGY4TXlLcW15WVhaendZPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PGRzOlJlZmVyZW5jZSBUeXBlPSJodHRwOi8vdXJpLmV0c2kub3JnLzAxOTAzI1NpZ25lZFByb3BlcnRpZXMiIFVSST0iI3hhZGVzLWlkLWUwNTAwMTY2YmQ4YjI4Njc0OGE2MTAwODQ1MjA0ZmZkIj48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvVFIvMjAwMS9SRUMteG1sLWMxNG4tMjAwMTAzMTUiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkczpEaWdlc3RWYWx1ZT5jV0N4ekw1eFJMc2c2ZFM2SUlPSnlidGxpUkJ6WGYrVU5ZNlowZVVjVTZVPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZSBJZD0idmFsdWUtaWQtZTA1MDAxNjZiZDhiMjg2NzQ4YTYxMDA4NDUyMDRmZmQiPmhCRVVmYjhZRElWZGRqUDhZWTAyc2l4Tyt6UTBHWkszb2J3SGlGWndidW01YzZMVktYWEw5UmJ2U0JMZ0dqYzd5WTBseWMzOVdjODRlWVpuMlpnT002RkhVeCtudG9mYURHTVVFbXNNWVR3WElYYk42RU9HQmtSb3ZlTExncGR3RWFrZWtLZC9yS0o4aFhvemZKa1MzUjNqRmc2WGNmUkl4NU9SMVFqRVVabllMZWo5K0kxMlhqWlVjczNIRHZDR0NLUEVsSWUzaUlQRnVhLzdDd1N0cTlJd2d3WEh1dDJrbXk5bnRnZllwT2R1djd1bU5wWFBIcUQzTldSVlVuRkY4aHJoT29HYkMxVWNRNS9sK0I5b2Z3a2ZQeFltaG91SWRMOCtSQ1BrUXBBbHpyL0xrYmpBTlVyNTZuYWUwaGFXVzVYOGEvUHN3UmtvUVREZ05NTDdtQT09PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlDNmpDQ0FkS2dBd0lCQWdJR0x0WVUxN3RYTUEwR0NTcUdTSWIzRFFFQkN3VUFNREF4R3pBWkJnTlZCQU1NRWxKdmIzUlRaV3htVTJsbmJtVmtSbUZyWlRFUk1BOEdBMVVFQ2d3SVJGTlRMWFJsYzNRd0hoY05NVGN3TmpBNE1URXlOakF4V2hjTk5EY3dOekEwTURjMU56STBXakFvTVJNd0VRWURWUVFEREFwVGFXZHVaWEpHWVd0bE1SRXdEd1lEVlFRS0RBaEVVMU10ZEdWemREQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU1JM2taaHRuaXBuK2lpWkhaOWF4OEZsZkU1T3cvY0Z3QlRmQUViM1IxWlFVcDYvQlFuQnQ3T28wSldCdGM5cWt2N0pVRGRjQkpYUFY1UVdTNUF5TVBIcHFRNzVIaXRqc3EvRnp1OGVIdGtLcEZpemN4R2E5Qlpka1FqaDRyU3J0TzFLanMwUmQ1RFF0V1Nna2VWQ0NOMDlrTjBac1owRU5ZK0lwOFF4U215enRzU3RrWVhkVUxxcHd6NEpFWFc5dno2NGVUYmRlNHZRSjZwakhHYXJKZjFnUU5FYzJYemhtSS9wclhMeXNXTnFDN2xaZzdQVVpVVHJkZWdBQlRVellDUkoxa1dCUlBtNHFvMExONDA1Yzk0UVFkNDVhNWtUZ293SHpFZ0xuQVFJMjh4ME0zQTU5VEtDK2llTmM2VkYxUHNUTHBVdzdQTkkyVnN0WDVqQXVhc0NBd0VBQWFNU01CQXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQ0s2TEdBMDFUUitybVU4cDZ5aEFpNE9rRE4yYjFkYklMOGw4aUNNWW9wTEN4eDh4cXEzdWJaQ094cWgxWDJqNnBnV3phcmIwYi9NVWl4MDBJb1V2TmJGT3hBVzdQQlpJS0RMbm02THNja1J4czFVMzJzQzlkMUxPSGUzV0tCTkI2R1pBTFQxZXdqaDdoU2JXamZ0bG1jb3ZxKzZlVkdBNWN2ZjJ1LzIrVGtLa3lIVi9OUjM5NG5YcmRzZHB2eWd3eXBFdFhqZXR6RDdVVDkzTnV3M3hjVjhWSWZ0SXZIZjlMalU3aCtVakdtS1hHOWMxNWVZcjNTelVtdjZreU9JMEJ2dzE0UFd0c1dHbDBRZE9TUnZJQkJyUDRhZENuR1RnamdqazlMVGNPOEI4Rktycis4bEhHdWMwYnA0bElVVG9pVWtHSUxYc2lFZUVnOVdBcW0rWHFPPC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PGRzOk9iamVjdD48eGFkZXM6UXVhbGlmeWluZ1Byb3BlcnRpZXMgeG1sbnM6eGFkZXM9Imh0dHA6Ly91cmkuZXRzaS5vcmcvMDE5MDMvdjEuMy4yIyIgVGFyZ2V0PSIjaWQtZTA1MDAxNjZiZDhiMjg2NzQ4YTYxMDA4NDUyMDRmZmQiPjx4YWRlczpTaWduZWRQcm9wZXJ0aWVzIElkPSJ4YWRlcy1pZC1lMDUwMDE2NmJkOGIyODY3NDhhNjEwMDg0NTIwNGZmZCI+PHhhZGVzOlNpZ25lZFNpZ25hdHVyZVByb3BlcnRpZXM+PHhhZGVzOlNpZ25pbmdUaW1lPjIwMjAtMDMtMzBUMDg6MzQ6MjFaPC94YWRlczpTaWduaW5nVGltZT48eGFkZXM6U2lnbmluZ0NlcnRpZmljYXRlVjI+PHhhZGVzOkNlcnQ+PHhhZGVzOkNlcnREaWdlc3Q+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTUxMiIvPjxkczpEaWdlc3RWYWx1ZT4xNHdNakRGemZzcWtkWlVzblBIMC9oK1pvOHJ6OERFd2lNcTJZTzF3TlRmcGxMM3drUTdFMGwyeVpQWWRlcUdLOVN4Q1RsenAxMVJORVVlTEtNc0NlUT09PC9kczpEaWdlc3RWYWx1ZT48L3hhZGVzOkNlcnREaWdlc3Q+PHhhZGVzOklzc3VlclNlcmlhbFYyPk1ENHdOS1F5TURBeEd6QVpCZ05WQkFNTUVsSnZiM1JUWld4bVUybG5ibVZrUm1GclpURVJNQThHQTFVRUNnd0lSRk5UTFhSbGMzUUNCaTdXRk5lN1Z3PT08L3hhZGVzOklzc3VlclNlcmlhbFYyPjwveGFkZXM6Q2VydD48L3hhZGVzOlNpZ25pbmdDZXJ0aWZpY2F0ZVYyPjx4YWRlczpTaWduYXR1cmVQb2xpY3lJZGVudGlmaWVyPjx4YWRlczpTaWduYXR1cmVQb2xpY3lJbXBsaWVkLz48L3hhZGVzOlNpZ25hdHVyZVBvbGljeUlkZW50aWZpZXI+PHhhZGVzOlNpZ25hdHVyZVByb2R1Y3Rpb25QbGFjZVYyLz48L3hhZGVzOlNpZ25lZFNpZ25hdHVyZVByb3BlcnRpZXM+PHhhZGVzOlNpZ25lZERhdGFPYmplY3RQcm9wZXJ0aWVzPjx4YWRlczpEYXRhT2JqZWN0Rm9ybWF0IE9iamVjdFJlZmVyZW5jZT0iI3ItaWQtZTA1MDAxNjZiZDhiMjg2NzQ4YTYxMDA4NDUyMDRmZmQtMSI+PHhhZGVzOk1pbWVUeXBlPnRleHQveG1sPC94YWRlczpNaW1lVHlwZT48L3hhZGVzOkRhdGFPYmplY3RGb3JtYXQ+PC94YWRlczpTaWduZWREYXRhT2JqZWN0UHJvcGVydGllcz48L3hhZGVzOlNpZ25lZFByb3BlcnRpZXM+PC94YWRlczpRdWFsaWZ5aW5nUHJvcGVydGllcz48L2RzOk9iamVjdD48ZHM6T2JqZWN0IElkPSJvLWlkLWUwNTAwMTY2YmQ4YjI4Njc0OGE2MTAwODQ1MjA0ZmZkLTEiPlBHaGxiR3h2UG5kdmNteGtQQzlvWld4c2J6ND08L2RzOk9iamVjdD48L2RzOlNpZ25hdHVyZT4=\",\n" +
                "    \"digestAlgorithm\" : null,\n" +
                "    \"name\" : \"sample-signed-xades-baseline-b.xml\"\n" +
                "  },\n" +
                "  \"extendProfileId\" : \"XADES_T\"\n" +
                "}", com.zetes.projects.bosa.signandvalidation.model.ExtendDocumentDTO.class);

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
                                                       SignatureAlgorithm signatureAlgorithm) {
        ProfileSignatureParameters profileParams = new ProfileSignatureParameters();
        profileParams.setProfileId(profileId);
        profileParams.setAsicContainerType(containerType);
        profileParams.setSignatureLevel(signatureLevel);
        profileParams.setSignaturePackaging(signaturePackaging);
        profileParams.setSignatureAlgorithm(signatureAlgorithm);
        profileParams.setReferenceDigestAlgorithm(referenceDigestAlgorithm);

        dao.save(profileParams);
    }

    private static void saveSigningType(SigningTypeDAO dao, String name, Boolean active, CertificateType... certificateTypes) {
        SigningType signingType = new SigningType();
        signingType.setName(name);
        signingType.setActive(active);
        signingType.setCertificateTypes(new HashSet<>(Arrays.asList(certificateTypes)));

        dao.save(signingType);
    }

}
