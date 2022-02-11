package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.signandvalidation.model.*;
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
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.ResponseEntity;

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
import static org.springframework.http.MediaType.APPLICATION_XML_VALUE;

public class XMLSigningControllerTest extends SigningControllerBaseTest {

    @MockBean
    private StorageService storageService;

    private String THE_BUCKET = "bucket";

    private String OUT_FILE_NAME = "out.xml";


    private String MAIN_XSLT_FILE_NAME = "XSLT.xslt";
    private String ROOT_XSLT_ELT = "SignedDoc";
    private String FILE_XSLT_ELT = "DataFile";
    private String MAIN_XSLT_FILE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                               "<" + ROOT_XSLT_ELT + " xsl:version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">" +
                                   "<xsl:for-each select=\"root/file\">" +
                                        "<" + FILE_XSLT_ELT + " id=\"{@id}\" FileName=\"{@name}\"></"+ FILE_XSLT_ELT + ">" +
                                   "</xsl:for-each>" +
                               "</" + ROOT_XSLT_ELT + ">";

    @AllArgsConstructor
    private enum FileDef {
        F1("aFile.xml", "1", MimeType.XML, "QSBUZXN0", "pinp.xslt", "XSLT1", false),
        F2("bFile.xml", "deux", MimeType.XML, "QSBUZXN0", "pimp1.xslt", "XSLT2", true),
        F3("test.pdf", "drie", MimeType.PDF, "QSBUZXN0", null, null, true),
        F4("dFile.pdf", "FOUR", MimeType.PDF, "QSBUZXN0", null, null, true);

        private String name;
        private String id;
        private MimeType type;
        private String data;
        private String xslt;
        private String xsltData;
        private Boolean rdConf;

        XmlSignInput getXmlSignInput() { return new XmlSignInput(name, xslt, id, rdConf); }
        public static FileDef find(String name) { for (FileDef fd : values()) if (name.equals(fd.name) || name.equals(fd.xslt)) return fd; return null; }
    }

    private static String unSignedXmlFile = null;

    @Test
    public void testSignCreateToken() throws Exception {
        Mockito.when(storageService.isValidAuth(any(),any())).thenReturn(true);
        Mockito.when(storageService.getFileAsStream(eq(THE_BUCKET),eq(MAIN_XSLT_FILE_NAME))).thenReturn(new ByteArrayInputStream(MAIN_XSLT_FILE.getBytes()));

        doAnswer(invocation -> {
            // When storing the secret key, prepare the next mock "get" call
            Mockito.when(storageService.getFileAsBytes(isNull(), eq(invocation.getArgument(1)), eq(false))).thenReturn(invocation.getArgument(2));
            return null;
        }).when(storageService).storeFile(isNull(), any(), any());

        doAnswer(invocation -> {
            if (unSignedXmlFile != null) {
                // Check that the output XML file matches all expected transformations
                assertEquals(unSignedXmlFile, new String((byte[]) invocation.getArgument(2)));
                unSignedXmlFile = null;     // Only check the file the first time (Not yet signed)
            }
            // Pass the written file to the next read
            Mockito.when(storageService.getFileAsBytes(eq(THE_BUCKET), eq(OUT_FILE_NAME), eq(true))).thenReturn(invocation.getArgument(2));
            return null;
        }).when(storageService).storeFile(eq(THE_BUCKET),eq(OUT_FILE_NAME), any());

        // Prepare expected Unsigned XML output, mock loading of each file
        StringBuilder sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><" + ROOT_XSLT_ELT + ">");
        List<XmlSignInput> inFiles = new ArrayList<XmlSignInput>();
        for(FileDef fd : FileDef.values()) {
            inFiles.add(fd.getXmlSignInput());
            Mockito.when(storageService.getFileAsB64String(eq(THE_BUCKET),eq(fd.name))).thenReturn(fd.data);
            Mockito.when(storageService.getFileInfo(eq(THE_BUCKET),eq(fd.name))).thenReturn(new FileStoreInfo(fd.type.getMimeTypeString(), "HASH", fd.data.length()));
            Mockito.when(storageService.getFileAsStream(eq(THE_BUCKET),eq(fd.name))).thenReturn(new ByteArrayInputStream(fd.data.getBytes()));
            if (fd.xslt != null) {
                Mockito.when(storageService.getFileInfo(eq(THE_BUCKET),eq(fd.xslt))).thenReturn(new FileStoreInfo(APPLICATION_XML_VALUE, "HASH", fd.xsltData.length()));
                Mockito.when(storageService.getFileAsStream(eq(THE_BUCKET),eq(fd.xslt))).thenReturn(new ByteArrayInputStream(fd.xsltData.getBytes()));
            }
            sb.append("<" + FILE_XSLT_ELT + " FileName=\"" + fd.name + "\" id=\"" + fd.id + "\">" + fd.data + "</" + FILE_XSLT_ELT + ">");
        }
        sb.append("</" + ROOT_XSLT_ELT + ">");
        unSignedXmlFile = sb.toString();

        // Start testing
        CreateSignFlowDTO csf = new CreateSignFlowDTO(THE_BUCKET, "pwd", "XADES_LTA", inFiles, OUT_FILE_NAME);
        csf.setOutXslt(MAIN_XSLT_FILE_NAME);

        // Create XML to sign
        String token = this.restTemplate.postForObject(LOCALHOST + port + XMLSigningController.ENDPOINT + XMLSigningController.FLOW_REST_RESOURCE, csf, String.class);
        System.out.println(token);

        // First call from UI to get a view of the various files to display
        FileInfoForTokenDTO fift = this.restTemplate.postForObject(LOCALHOST + port + XMLSigningController.ENDPOINT + XMLSigningController.GET_FILEINFO_FOR_TOKEN, token, FileInfoForTokenDTO.class);

        for(XmlSignInput input : fift.getInputs()) {
            // Per file call to display content & XSLT
            ResponseEntity<byte[]> file = this.restTemplate.getForEntity(LOCALHOST + port + XMLSigningController.ENDPOINT + XMLSigningController.GET_FILE_FOR_TOKEN + "/" + token + "/" + input.getFileName(), byte[].class);

            FileDef fd = FileDef.find(input.getFileName());
            assertEquals(new String(file.getBody()), fd.data);
            assertEquals(file.getHeaders().getContentType().toString(), fd.type.getMimeTypeString());

            if (input.getDisplayXslt() != null) {
                file = this.restTemplate.getForEntity(LOCALHOST + port + XMLSigningController.ENDPOINT + XMLSigningController.GET_FILE_FOR_TOKEN + "/" + token + "/" + input.getDisplayXslt(), byte[].class);

                fd = FileDef.find(input.getFileName());
                assertEquals(new String(file.getBody()), fd.xsltData);
                assertEquals(file.getHeaders().getContentType().toString(), APPLICATION_XML_VALUE);
            }
        }

        Pkcs12SignatureToken sigToken = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );

        // Get hash & algo that must be signed
        ClientSignatureParameters csp = getClientSignatureParameters(sigToken.getKeys().get(0));
        GetDataToSignForTokenDTO dto = new GetDataToSignForTokenDTO(token, "Not used !", csp);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + XMLSigningController.ENDPOINT + XMLSigningController.GET_DATA_TO_SIGN_FOR_TOKEN, dto, DataToSignDTO.class);

        // Sign hash
        SignatureValue signatureValue = sigToken.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), sigToken.getKeys().get(0));

        // Sign file & return its content
        csp.setSigningDate(dataToSign.getSigningDate());
        SignDocumentForTokenDTO sdto = new SignDocumentForTokenDTO(token, csp, signatureValue.getValue());
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + XMLSigningController.ENDPOINT + XMLSigningController.SIGN_DOCUMENT_FOR_TOKEN, sdto, RemoteDocument.class);

        assertNotNull(signedDocument);

        System.out.println(new String(signedDocument.getBytes()));
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
