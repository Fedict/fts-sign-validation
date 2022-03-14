package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.signandvalidation.model.*;
import com.zetes.projects.bosa.signandvalidation.service.BosaRemoteDocumentValidationService;
import com.zetes.projects.bosa.signandvalidation.service.ReportsService;
import com.zetes.projects.bosa.signandvalidation.service.StorageService;
import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.zetes.projects.bosa.signingconfigurator.model.PolicyParameters;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import lombok.AllArgsConstructor;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.zetes.projects.bosa.signandvalidation.controller.SigningController.*;
import static com.zetes.projects.bosa.signandvalidation.model.DisplayType.*;
import static com.zetes.projects.bosa.signandvalidation.model.DisplayType.Content;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.MediaType.APPLICATION_PDF;
import static org.springframework.http.MediaType.APPLICATION_XML;

public class SigningControllerTest extends SigningControllerBaseTest {

    @MockBean
    private StorageService storageService;

    @MockBean
    private ReportsService reportsService;

    @MockBean
    private BosaRemoteDocumentValidationService validationService;

    private static final String THE_BUCKET = "bucket";

    private static final String OUT_FILE_NAME = "out.xml";

    private static final String MAIN_XSLT_FILE_NAME = "XSLT.xslt";
    private static final String ROOT_XSLT_ELT = "SignedDoc";
    private static final String FILE_XSLT_ELT = "DataFile";
    private static final String XSLT_COMMENT = " Created By BosaSign 1.0 ";
    private static final String MAIN_XSLT_FILE = "<?xml version=\"1.0\"?>" +
            "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">" +
            "<xsl:template match=\"/\">" +
            "<xsl:comment>" + XSLT_COMMENT + "</xsl:comment>" +
            "	<" + ROOT_XSLT_ELT + ">" +
            "		<xsl:for-each select=\"root/file\">" +
            "			<" + FILE_XSLT_ELT + " iD=\"{@id}\" FileName=\"{tokenize(@name, '/')[last()]}\" MimeType=\"{tokenize(@name, '\\.')[last()]}\"></"+ FILE_XSLT_ELT + ">" +
            "		</xsl:for-each>" +
            "	</" + ROOT_XSLT_ELT + ">" +
            "</xsl:template>" +
            "</xsl:stylesheet>";


    @AllArgsConstructor
    private enum FileDef {
        F1("root/aFile.xml", "1", APPLICATION_XML, "QSBUZXN0", "pinp.xslt", "XSLT1", false, Content),
        F2("bFile.xml", "deux", APPLICATION_XML, "QSBUZXN0", "pimp1.xslt", "XSLT2", true, Content),
        F3("test.pdf", "drie", APPLICATION_PDF, "QSBUZXN0", null, null, false, No),
        F4("dFile.pdf", "FOUR", APPLICATION_PDF, "QSBUZXN0", null, null, true, Content);

        private String name;
        private String id;
        private MediaType type;
        private String data;
        private String xslt;
        private String xsltData;
        private Boolean rdConf;
        private DisplayType dt;

        SignInput getXmlSignInput() { return new SignInput(name, id, rdConf, dt, xslt); }
        public static FileDef find(String name) { for (FileDef fd : values()) if (name.equals(fd.name) || name.equals(fd.xslt)) return fd; return null; }
    }

    private static String unSignedXmlFile = null;

    @Test
    public void testSignCreateToken() throws Exception {
        Mockito.when(storageService.isValidAuth(any(),any())).thenReturn(true);
        Mockito.when(storageService.getFileAsStream(eq(THE_BUCKET),eq(MAIN_XSLT_FILE_NAME))).thenReturn(new ByteArrayInputStream(MAIN_XSLT_FILE.getBytes()));

        WSReportsDTO reportsDto = new WSReportsDTO();
        Mockito.when(validationService.validateDocument(any(),any(), any(), any())).thenReturn(reportsDto);
        SignatureIndicationsDTO indications = new SignatureIndicationsDTO();
        indications.setIndication(Indication.TOTAL_PASSED);
        Mockito.when(reportsService.getSignatureIndicationsDto(eq(reportsDto))).thenReturn(indications);

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
        StringBuilder sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!--" + XSLT_COMMENT + "--><" + ROOT_XSLT_ELT + ">");
        List<SignInput> inFiles = new ArrayList<SignInput>();
        for(FileDef fd : FileDef.values()) {
            inFiles.add(fd.getXmlSignInput());
            Mockito.when(storageService.getFileAsB64String(eq(THE_BUCKET),eq(fd.name))).thenReturn(fd.data);
            Mockito.when(storageService.getFileInfo(eq(THE_BUCKET),eq(fd.name))).thenReturn(new FileStoreInfo(fd.type, "HASH", fd.data.length()));
            Mockito.when(storageService.getFileAsStream(eq(THE_BUCKET),eq(fd.name))).thenReturn(new ByteArrayInputStream(fd.data.getBytes()));
            if (fd.xslt != null) {
                Mockito.when(storageService.getFileInfo(eq(THE_BUCKET),eq(fd.xslt))).thenReturn(new FileStoreInfo(APPLICATION_XML, "HASH", fd.xsltData.length()));
                Mockito.when(storageService.getFileAsStream(eq(THE_BUCKET),eq(fd.xslt))).thenReturn(new ByteArrayInputStream(fd.xsltData.getBytes()));
            }

            sb.append("<" + FILE_XSLT_ELT + " FileName=\"" + lastOccurenceOf(fd.name, '/') + "\" MimeType=\"" + lastOccurenceOf(fd.name, '.') + "\" iD=\"" + fd.id + "\">" + fd.data + "</" + FILE_XSLT_ELT + ">");
        }
        sb.append("</" + ROOT_XSLT_ELT + ">");
        unSignedXmlFile = sb.toString();

        // Start testing
        GetTokenForDocumentsDTO gtfd = new GetTokenForDocumentsDTO(THE_BUCKET, "pwd", "XADES_B", inFiles, OUT_FILE_NAME);
        gtfd.setOutXslt(MAIN_XSLT_FILE_NAME);
        gtfd.setOutDownload(true);

        // Create XML to sign
        String token = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + GET_TOKEN_FOR_DOCUMENTS, gtfd, String.class);
        System.out.println(token);

        // First call from UI to get a view of the various files to display
        DocumentMetadataDTO fift = this.restTemplate.getForObject(LOCALHOST + port + ENDPOINT + GET_METADATA_FOR_TOKEN + "?token=" + token, DocumentMetadataDTO.class);

        int inputIndex = 0;
        for(SignInputMetadata input : fift.getInputs()) {
            // Per file call to display content & XSLT
            ResponseEntity<byte[]> file = this.restTemplate.getForEntity(LOCALHOST + port + ENDPOINT + GET_FILE_FOR_TOKEN + "/" + token + "/" + GetFileType.DOC + "/" + inputIndex, byte[].class);

            FileDef fd = FileDef.find(input.getFileName());
            assertEquals(new String(file.getBody()), fd.data);
            assertEquals(file.getHeaders().getContentType(), fd.type);

            if (input.getDisplayXslt() != null) {
                file = this.restTemplate.getForEntity(LOCALHOST + port + ENDPOINT + GET_FILE_FOR_TOKEN + "/" + token + "/" + GetFileType.XSLT + "/" + inputIndex, byte[].class);

                fd = FileDef.find(input.getFileName());
                assertEquals(new String(file.getBody()), fd.xsltData);
                assertEquals(file.getHeaders().getContentType(), APPLICATION_XML);
            }
            inputIndex++;
        }

        Pkcs12SignatureToken sigToken = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );

        // Get hash & algo that must be signed
        ClientSignatureParameters csp = getClientSignatureParameters(sigToken.getKeys().get(0));
        GetDataToSignForTokenDTO dto = new GetDataToSignForTokenDTO(token, "Not used !", csp);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + GET_DATA_TO_SIGN_FOR_TOKEN, dto, DataToSignDTO.class);

        // Sign hash
        SignatureValue signatureValue = sigToken.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), sigToken.getKeys().get(0));

        // Sign file & return its content
        csp.setSigningDate(dataToSign.getSigningDate());
        SignDocumentForTokenDTO sdto = new SignDocumentForTokenDTO(token, csp, signatureValue.getValue());
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + SIGN_DOCUMENT_FOR_TOKEN, sdto, RemoteDocument.class);

        assertNotNull(signedDocument);

        System.out.println(new String(signedDocument.getBytes()));
    }

    private static String lastOccurenceOf(String name, char c) {
        int pos = name.lastIndexOf(c);
        return pos == -1 ? name : name.substring(pos + 1);
    }

    @Test
    public void testSigningAndExtensionXades() throws Exception {
        WSReportsDTO reportsDto = new WSReportsDTO();
        Mockito.when(validationService.validateDocument(any(),any(), any(), any())).thenReturn(reportsDto);
        SignatureIndicationsDTO indications = new SignatureIndicationsDTO();
        indications.setIndication(Indication.TOTAL_PASSED);
        Mockito.when(reportsService.getSignatureIndicationsDto(eq(reportsDto))).thenReturn(indications);

        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

        // get data to sign
        GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, "XADES_B", clientSignatureParameters);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + GET_DATA_TO_SIGN, dataToSignDTO, DataToSignDTO.class);
        assertNotNull(dataToSign);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentDTO signDocumentDTO = new SignDocumentDTO(toSignDocument, "XADES_B", clientSignatureParameters, signatureValue.getValue());
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + SIGN_DOCUMENT, signDocumentDTO, RemoteDocument.class);
        assertNotNull(signedDocument);

        // extend document
        ExtendDocumentDTO extendDocumentDTO = new ExtendDocumentDTO(signedDocument, "XADES_T", null);
        RemoteDocument extendedDocument = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + EXTEND_DOCUMENT, extendDocumentDTO, RemoteDocument.class);
        assertNotNull(extendedDocument);

        InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
        iMD.save("target/test.xml");
    }

    @Test
    public void testSigningCades() throws Exception {
        WSReportsDTO reportsDto = new WSReportsDTO();
        Mockito.when(validationService.validateDocument(any(),any(), any(), any())).thenReturn(reportsDto);
        SignatureIndicationsDTO indications = new SignatureIndicationsDTO();
        indications.setIndication(Indication.TOTAL_PASSED);
        Mockito.when(reportsService.getSignatureIndicationsDto(eq(reportsDto))).thenReturn(indications);

        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

        // get data to sign
        GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, "CADES_B", clientSignatureParameters);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + GET_DATA_TO_SIGN, dataToSignDTO, DataToSignDTO.class);
        assertNotNull(dataToSign);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentDTO signDocumentDTO = new SignDocumentDTO(toSignDocument, "CADES_B", clientSignatureParameters, signatureValue.getValue());
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + SIGN_DOCUMENT, signDocumentDTO, RemoteDocument.class);
        assertNotNull(signedDocument);

        InMemoryDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        iMD.save("target/test.zip");
    }

    @Test
    public void testSigningPades() throws Exception {
        WSReportsDTO reportsDto = new WSReportsDTO();
        Mockito.when(validationService.validateDocument(any(),any(), any(), any())).thenReturn(reportsDto);
        SignatureIndicationsDTO indications = new SignatureIndicationsDTO();
        indications.setIndication(Indication.TOTAL_PASSED);
        Mockito.when(reportsService.getSignatureIndicationsDto(eq(reportsDto))).thenReturn(indications);

        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.pdf"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

        // get data to sign
        GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, "PADES_B", clientSignatureParameters);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + GET_DATA_TO_SIGN, dataToSignDTO, DataToSignDTO.class);
        assertNotNull(dataToSign);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentDTO signDocumentDTO = new SignDocumentDTO(toSignDocument, "PADES_B", clientSignatureParameters, signatureValue.getValue());
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + SIGN_DOCUMENT, signDocumentDTO, RemoteDocument.class);
        assertNotNull(signedDocument);

        InMemoryDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        iMD.save("target/test.pdf");
    }

    @Test
    public void testTimestampPdf() throws Exception {
        FileDocument fileToTimestamp = new FileDocument(new File("src/test/resources/sample.pdf"));
        RemoteDocument remoteDocument = RemoteDocumentConverter.toRemoteDocument(fileToTimestamp);

        TimestampDocumentDTO timestampOneDocumentDTO = new TimestampDocumentDTO(remoteDocument, "PROFILE_1");
        RemoteDocument timestampedDocument = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + TIMESTAMP_DOCUMENT, timestampOneDocumentDTO, RemoteDocument.class);

        assertNotNull(timestampedDocument);

        InMemoryDocument iMD = new InMemoryDocument(timestampedDocument.getBytes());
        // iMD.save("target/testSigned.pdf");
        assertNotNull(iMD);
    }

    @Test
    public void testExpired() throws Exception {
        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/expired.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

        // get data to sign
        GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, "XADES_B", clientSignatureParameters);
        Map result = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + GET_DATA_TO_SIGN, dataToSignDTO, Map.class);

        assertEquals(BAD_REQUEST.value(), result.get("status"));
        assert(result.get("message").toString().endsWith(SIGN_CERT_EXPIRED + "||exp. date = 2021.03.06 12:28:05"));
    }

    @Test
    public void testNoChain() throws Exception {
        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/nochain.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

        // get data to sign
        GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, "XADES_B", clientSignatureParameters);
        Map result = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + GET_DATA_TO_SIGN, dataToSignDTO, Map.class);

        assertEquals(BAD_REQUEST.value(), result.get("status"));
        assert(result.get("message").toString().endsWith("CERT_CHAIN_INCOMPLETE" + "||cert count: 1"));
    }

    @Test
    public void testSignXadesMultiDocument() throws Exception {
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
            targets.add(new SignElement(fDef.id, fDef.type.toString()));
            sb.append("<file id=\"").append(fDef.id).append("\" name=\"").append(fDef.name).append("\">").append(fDef.data).append("</file>");
        }
        sb.append("</root>");
        System.out.println(sb.toString());
        RemoteDocument fileToSign = new RemoteDocument(sb.toString().getBytes(), "aFile.xml");

        PolicyParameters policy = null;
        // TODO The current code needs access to a proxy to validate the Policies, therefore it can't run on the pipelines
//      policy = new PolicyParameters("http://signinfo.eda.just.fgov.be/SignaturePolicy/pdf/Notary/BE_Justice_Signature_Policy_Notary_eID_Hum_v0.10_202109_Fr.pdf", "policyDesc", DigestAlgorithm.SHA256);

        // get data to sign
        GetDataToSignXMLElementsDTO prepareSignDto = new GetDataToSignXMLElementsDTO("XADES_LTA", fileToSign, clientSignatureParameters, policy, targets);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + GET_DATA_TO_SIGN_XADES_MULTI_DOC, prepareSignDto, DataToSignDTO.class);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignXMLElementsDTO signDto = new SignXMLElementsDTO("XADES_LTA", fileToSign, clientSignatureParameters, policy, targets, signatureValue.getValue());
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + SIGN_DOCUMENT_XADES_MULTI_DOC, signDto, RemoteDocument.class);
        assertNotNull(signedDocument);

        System.out.println(signedDocument.getName());
        System.out.println(new String(signedDocument.getBytes()));
    }
}
