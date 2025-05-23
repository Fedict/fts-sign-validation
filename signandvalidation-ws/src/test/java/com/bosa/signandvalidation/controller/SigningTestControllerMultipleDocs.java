package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.SignAndValidationBaseTest;
import com.bosa.signandvalidation.model.*;
import com.bosa.signandvalidation.model.SignatureLevel;
import com.bosa.signingconfigurator.dao.ProfileSignatureParametersDao;
import com.bosa.signingconfigurator.dao.ProfileTimestampParametersDao;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.bosa.signingconfigurator.model.ProfileSignatureParameters;
import com.bosa.signingconfigurator.model.ProfileTimestampParameters;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static eu.europa.esig.dss.enumerations.DigestAlgorithm.SHA256;
import static eu.europa.esig.dss.enumerations.TimestampContainerForm.ASiC_E;
import static javax.xml.crypto.dsig.Transform.ENVELOPED;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SigningTestControllerMultipleDocs extends SignAndValidationBaseTest {

    @Autowired
    ObjectMapper mapper;

    public static final String GETDATATOSIGN_ENDPOINT = "/signing/getDataToSignMultiple";
    public static final String SIGNDOCUMENT_ENDPOINT = "/signing/signDocumentMultiple";
    public static final String EXTENDDOCUMENT_ENDPOINT = "/signing/extendDocumentMultiple";
    public static final String TIMESTAMP_ENDPOINT = "/signing/timestampDocumentMultiple";

    @BeforeAll
    public static void fillDB(ApplicationContext applicationContext) {
        ProfileSignatureParametersDao profileSigParamDao = applicationContext.getBean(ProfileSignatureParametersDao.class);
        profileSigParamDao.deleteAll();
        saveProfileSignatureParameters(profileSigParamDao, "XADES_B", ASiCContainerType.ASiC_E, SignatureLevel.XAdES_BASELINE_B,
                SignaturePackaging.DETACHED, null, SHA256);
        saveProfileSignatureParameters(profileSigParamDao, "XADES_T", ASiCContainerType.ASiC_E, SignatureLevel.XAdES_BASELINE_T,
                SignaturePackaging.DETACHED, DigestAlgorithm.SHA256, SHA256);

        ProfileTimestampParametersDao timestampParamDao = applicationContext.getBean(ProfileTimestampParametersDao.class);
        timestampParamDao.deleteAll();
        saveProfileTimestampParameters(timestampParamDao, "PROFILE_1", SHA256, ENVELOPED, ASiC_E);
    }

    @Test
    public void testSigningAndExtension() throws Exception {
        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
        List<RemoteDocument> toSignDocuments = new ArrayList<>();
        toSignDocuments.add(new RemoteDocument(DSSUtils.toByteArray(fileToSign), fileToSign.getName()));
        toSignDocuments.add(new RemoteDocument("Hello world!".getBytes(), "test.bin"));

        // get data to sign
        GetDataToSignMultipleDTO dataToSignDTO = new GetDataToSignMultipleDTO(toSignDocuments, "XADES_B", clientSignatureParameters, "ID");
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + GETDATATOSIGN_ENDPOINT, dataToSignDTO, DataToSignDTO.class);
        assertNotNull(dataToSign);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        SignDocumentMultipleDTO signDocumentDTO = new SignDocumentMultipleDTO(toSignDocuments, "XADES_B", clientSignatureParameters, signatureValue.getValue(), null, "ID");
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + SIGNDOCUMENT_ENDPOINT, signDocumentDTO, RemoteDocument.class);
        assertNotNull(signedDocument);

        // extend document
        ExtendDocumentDTO extendDocumentDTO = new ExtendDocumentDTO(signedDocument, "XADES_T", toSignDocuments, "ID");
        RemoteDocument extendedDocument = this.restTemplate.postForObject(LOCALHOST + port + EXTENDDOCUMENT_ENDPOINT, extendDocumentDTO, RemoteDocument.class);
        assertNotNull(extendedDocument);

        InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
        iMD.save("target/test.asice");
    }

    @Test
    public void timestampMultipleDocumentsTest() {
        List<DSSDocument> documentsToSign = new ArrayList<DSSDocument>(Arrays.asList(
                new FileDocument(new File("src/test/resources/sample.xml")), new FileDocument(new File("src/test/resources/sample.pdf"))));
        List<RemoteDocument> remoteDocuments = RemoteDocumentConverter.toRemoteDocuments(documentsToSign);

        TimestampDocumentMultipleDTO timestampMultipleDocumentDTO = new TimestampDocumentMultipleDTO(remoteDocuments, "PROFILE_1", "ID");
        RemoteDocument timestampedDocument = this.restTemplate.postForObject(LOCALHOST + port + TIMESTAMP_ENDPOINT, timestampMultipleDocumentDTO, RemoteDocument.class);

        assertNotNull(timestampedDocument);

        InMemoryDocument iMD = new InMemoryDocument(timestampedDocument.getBytes());
        // iMD.save("target/testSigned.asice");
        assertNotNull(iMD);
    }

    private ClientSignatureParameters getClientSignatureParameters(DSSPrivateKeyEntry dssPrivateKeyEntry) {
        List<RemoteCertificate> chain = new ArrayList<>();
        for (CertificateToken token : dssPrivateKeyEntry.getCertificateChain()) {
            chain.add(new RemoteCertificate(token.getEncoded()));
        }

        ClientSignatureParameters clientSignatureParameters = new ClientSignatureParameters();
        clientSignatureParameters.setSigningCertificate(new RemoteCertificate(dssPrivateKeyEntry.getCertificate().getEncoded()));
        clientSignatureParameters.setCertificateChain(chain);
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
