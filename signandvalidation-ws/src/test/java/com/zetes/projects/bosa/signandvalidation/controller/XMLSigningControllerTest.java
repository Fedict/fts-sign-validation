package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.signandvalidation.model.*;
import com.zetes.projects.bosa.signandvalidation.service.ObjectStorageService;
import com.zetes.projects.bosa.signandvalidation.service.StorageService;
import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.zetes.projects.bosa.signingconfigurator.model.PolicyParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import lombok.AllArgsConstructor;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;

public class XMLSigningControllerTest extends SigningControllerBaseTest {

    @MockBean
    private StorageService storageService;

    @Autowired
    private ObjectStorageService realObjStorageService;

    private String THE_BUCKET = "bucket";

    private String XSLT_FILE_NAME = "XSLT.xslt";
    private String OUT_FILE_NAME = "out.xml";

    private String XSLT_FILE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                               "<SignedDoc xsl:version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">" +
                                   "<xsl:for-each select=\"root/file\">" +
                                        "<DataFile id=\"{@id}\" FileName=\"{@name}\"></DataFile>" +
                                   "</xsl:for-each>" +
                               "</SignedDoc>";

    private String START_FILE = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><SignedDoc><DataFile FileName=\"aFile.xml\" id=\"1\">QSBUZXN0</DataFile><DataFile FileName=\"bFile.xml\" id=\"deux\">QSBUZXN0</DataFile><DataFile FileName=\"cFile.pdf\" id=\"drie\">QSBUZXN0</DataFile><DataFile FileName=\"dFile.pdf\" id=\"FOUR\">QSBUZXN0</DataFile></SignedDoc>";





    @AllArgsConstructor
    private enum FileDef {
        F1("aFile.xml", "1", MimeType.XML, "QSBUZXN0", "pinp.xslt", true, false),
        F2("bFile.xml", "deux", MimeType.XML, "QSBUZXN0", "", false, true),
        F3("cFile.pdf", "drie", MimeType.PDF, "QSBUZXN0", null, false, true),
        F4("dFile.pdf", "FOUR", MimeType.PDF, "QSBUZXN0", null, true, true);

        private String name;
        private String id;
        private MimeType type;
        private String data;
        private String xslt;
        private Boolean noDownl;
        private Boolean rdConf;

        XmlSignInput getXmlSignInput() { return new XmlSignInput(name, id, xslt, noDownl, rdConf); }
    }

    @Test
    public void testSignCreate() throws Exception {
        Mockito.reset(storageService);
        Mockito.when(storageService.isValidAuth(any(),any())).thenReturn(true);
        Mockito.when(storageService.getFileAsStream(eq(THE_BUCKET),eq(XSLT_FILE_NAME))).thenReturn(new ByteArrayInputStream(XSLT_FILE.getBytes()));
        doAnswer(invocation -> {
            assertEquals(START_FILE, new String((byte [])invocation.getArgument(2)));
            return null;
        }).when(storageService).storeFile(eq(THE_BUCKET),eq(OUT_FILE_NAME), any());

        List<XmlSignInput> inFiles = new ArrayList<XmlSignInput>();
        for(FileDef fd : FileDef.values()) {
            inFiles.add(fd.getXmlSignInput());
            Mockito.when(storageService.getFileAsString(eq(THE_BUCKET),eq(fd.name))).thenReturn(fd.data);
        }

        CreateSignFlowDTO csf = new CreateSignFlowDTO(THE_BUCKET, "pwd", "XADES_LTA", inFiles, OUT_FILE_NAME);
        csf.setOutXslt(XSLT_FILE_NAME);

        String token = this.restTemplate.postForObject(LOCALHOST + port + XMLSigningController.ENDPOINT + XMLSigningController.FLOW_REST_RESOURCE, csf, String.class);
        System.out.println(token);
    }

        @Test
    public void testSignXML() throws Exception {
        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);
        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        StringBuilder sb = new StringBuilder("<root>");
        List<SignElement> targets = new ArrayList<>();
        for(FileDef fDef : FileDef.values()) {
            targets.add(new SignElement(fDef.id, fDef.type));
            sb.append("<file id=\"").append(fDef.id).append("\" name=\"").append(fDef.name).append("\">").append(fDef.data).append("</file>");
        }
        sb.append("</root>");
        System.out.println(sb.toString());
        RemoteDocument fileToSign = new RemoteDocument(sb.toString().getBytes(), "aFile.xml");

        PolicyParameters policy = new PolicyParameters("http://signinfo.eda.just.fgov.be/SignaturePolicy/pdf/Notary/BE_Justice_Signature_Policy_Notary_eID_Hum_v0.10_202109_Fr.pdf", "policyDesc", DigestAlgorithm.SHA256);

        // get data to sign
        GetDataToSignXMLElementsDTO prepareSignDto = new GetDataToSignXMLElementsDTO("XADES_LTA", fileToSign, clientSignatureParameters, policy, targets);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + XMLSigningController.ENDPOINT + XMLSigningController.GET_DATA_TO_SIGN, prepareSignDto, DataToSignDTO.class);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignXMLElementsDTO signDto = new SignXMLElementsDTO("XADES_LTA", fileToSign, clientSignatureParameters, policy, targets, signatureValue.getValue());
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + XMLSigningController.ENDPOINT + XMLSigningController.SIGN_DOCUMENT, signDto, RemoteDocument.class);
        assertNotNull(signedDocument);

        System.out.println(signedDocument.getName());
        System.out.println(new String(signedDocument.getBytes()));

        /*

        prepareSignDto = new PrepareSignXMLElementsDTO("XADES_LTA", signedDocument, clientSignatureParameters, policy, targets);
        dataToSign = this.restTemplate.postForObject(LOCALHOST + port + XMLSigningController.ENDPOINT + XMLSigningController.GET_DATA_TO_SIGN, prepareSignDto, DataToSignDTO.class);

        // sign
        signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        signDto = new SignXMLElementsDTO("XADES_LTA", signedDocument, clientSignatureParameters, policy, targets, signatureValue.getValue());
        signedDocument = this.restTemplate.postForObject(LOCALHOST + port + XMLSigningController.ENDPOINT + XMLSigningController.SIGN_DOCUMENT, signDto, RemoteDocument.class);
        assertNotNull(signedDocument);

        System.out.println(signedDocument.getName());
        System.out.println(new String(signedDocument.getBytes()));
         */

    }
}
