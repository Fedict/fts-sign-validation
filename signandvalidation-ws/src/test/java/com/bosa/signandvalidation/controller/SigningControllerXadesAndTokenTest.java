package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.*;
import com.bosa.signandvalidation.service.BosaRemoteDocumentValidationService;
import com.bosa.signandvalidation.service.ReportsService;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.bosa.signandvalidation.service.StorageService;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import lombok.AllArgsConstructor;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.http.MediaType.APPLICATION_PDF;
import static org.springframework.http.MediaType.APPLICATION_XML;

public class SigningControllerXadesAndTokenTest extends SigningControllerBaseTest {

        /*

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
            "			<" + FILE_XSLT_ELT + " id=\"{@id}\" FileName=\"{tokenize(@name, '/')[last()]}\" MimeType=\"{tokenize(@name, '\\.')[last()]}\"></"+ FILE_XSLT_ELT + ">" +
            "		</xsl:for-each>" +
            "	</" + ROOT_XSLT_ELT + ">" +
            "</xsl:template>" +
            "</xsl:stylesheet>";


    @AllArgsConstructor
    private enum FileDef {
        F1("root/aFile.xml", "Uno", APPLICATION_XML, "QSBUZXN0", "pinp.xslt", "XSLT1"),
        F2("bFile.xml", "deux", APPLICATION_XML, "QSBUZXN0", "pimp1.xslt", "XSLT2"),
        F3("test.pdf", "drie", APPLICATION_PDF, "QSBUZXN0", null, null),
        F4("dFile.pdf", "FOUR", APPLICATION_PDF, "QSBUZXN0", null, null);

        private final String name;
        private final String id;
        private final MediaType type;
        private final String data;
        private final String xslt;
        private final String xsltData;

        SignInput getXmlSignInput() { return new SignInput(name, id, xslt, null,  null,null, null, null, false, false); }
        public static FileDef find(String name) {
            for (FileDef fd : values()) {
                String fdName = fd.name;
                int pos = fdName.lastIndexOf('/');
                fdName = pos == -1 ? fdName : fdName.substring(pos + 1);
                if (name.compareTo(fdName) == 0) return fd;
            }
            return null;
        }
    }

    private static String unSignedXmlFile;

    @Test
    public void testSignCreateToken() throws Exception {
        Mockito.when(storageService.isValidAuth(any(),any())).thenReturn(true);
        Mockito.when(storageService.getFileAsStream(eq(THE_BUCKET),eq(MAIN_XSLT_FILE_NAME))).thenReturn(new ByteArrayInputStream(MAIN_XSLT_FILE.getBytes()));

        SignatureFullValiationDTO reportsDto = new SignatureFullValiationDTO();
        Mockito.when(validationService.validateDocument(any(),any(), any(), any(), any())).thenReturn(reportsDto);
        SignatureIndicationsDTO indications = new SignatureIndicationsDTO();
        indications.setIndication(Indication.TOTAL_PASSED);
        Mockito.when(reportsService.getLatestSignatureIndicationsDto(eq(reportsDto), any())).thenReturn(indications);

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
        unSignedXmlFile = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!--" + XSLT_COMMENT + "--><" + ROOT_XSLT_ELT + ">";
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

            unSignedXmlFile += "<" + FILE_XSLT_ELT + " FileName=\"" + lastOccurenceOf(fd.name, '/') + "\" MimeType=\"" + lastOccurenceOf(fd.name, '.') + "\" id=\"" + fd.id + "\">" + fd.data + "</" + FILE_XSLT_ELT + ">";
        }
        unSignedXmlFile += "</" + ROOT_XSLT_ELT + ">";

        // Start testing
        GetTokenForDocumentsDTO gtfd = new GetTokenForDocumentsDTO(THE_BUCKET, "pwd", SignProfiles.XADES_MDOC_LTA.name(), inFiles, OUT_FILE_NAME);
        gtfd.setOutXsltPath(MAIN_XSLT_FILE_NAME);
        gtfd.setOutDownload(true);

        // Create XML to sign
        String token = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.GET_TOKEN_FOR_DOCUMENTS_URL, gtfd, String.class);
        System.out.println(token);

        // First call from UI to get a view of the various files to display
        DocumentMetadataDTO fift = this.restTemplate.getForObject(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.GET_METADATA_FOR_TOKEN_URL + "?token=" + token, DocumentMetadataDTO.class);

        int inputIndex = 0;
        for(SignInputMetadata input : fift.getInputs()) {
            // Per file call to display content & XSLT
            ResponseEntity<byte[]> file = this.restTemplate.getForEntity(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.GET_FILE_FOR_TOKEN_URL + "/" + token + "/" + GetFileType.DOC + "/" + inputIndex, byte[].class);

            FileDef fd = FileDef.find(input.getFileName());
            assertEquals(new String(file.getBody()), fd.data);
            assertEquals(file.getHeaders().getContentType(), fd.type);

            if (input.isHasDisplayXslt()) {
                file = this.restTemplate.getForEntity(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.GET_FILE_FOR_TOKEN_URL + "/" + token + "/" + GetFileType.XSLT + "/" + inputIndex, byte[].class);

                fd = FileDef.find(input.getFileName());
                assertEquals(new String(file.getBody()), fd.xsltData);
                assertEquals(file.getHeaders().getContentType(), APPLICATION_XML);
            }
            inputIndex++;
        }

        Pkcs12SignatureToken sigToken = new Pkcs12SignatureToken(
                Files.newInputStream(Paths.get("src/test/resources/citizen_nonrep.p12")),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );

        // Get hash & algo that must be signed
        ClientSignatureParameters csp = getClientSignatureParameters(sigToken.getKeys().get(0));
        HashForSignConsentDTO dto = new HashForSignConsentDTO(token, 0, csp);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.GET_HASH_FOR_SIGNATURE_CONSENT_URL, dto, DataToSignDTO.class);

        // Sign hash
        SignatureValue signatureValue = sigToken.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), sigToken.getKeys().get(0));

        // Sign file & return its content
        csp.setSigningDate(dataToSign.getSigningDate());
        ConsentForTokenDTO sdto = new ConsentForTokenDTO(token, 0, csp, signatureValue.getValue());

        Map documentIsSigned = signSocumentAndWaitForResult(sdto, Map.class);
        assertTrue((Boolean)documentIsSigned.get("done"));
    }

    private static String lastOccurenceOf(String name, char c) {
        int pos = name.lastIndexOf(c);
        return pos == -1 ? name : name.substring(pos + 1);
    }

    @Test
    public void testSignXadesMultiDocument() throws Exception {
        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                Files.newInputStream(Paths.get("src/test/resources/citizen_nonrep.p12")),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);
        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        StringBuilder sb = new StringBuilder("<root>");
        List<String> targets = new ArrayList<>();
        for(SigningControllerXadesAndTokenTest.FileDef fDef : SigningControllerXadesAndTokenTest.FileDef.values()) {
            targets.add(fDef.id);
            sb.append("<file id=\"").append(fDef.id).append("\" name=\"").append(fDef.name).append("\">").append(fDef.data).append("</file>");
        }
        sb.append("</root>");
        System.out.println(sb);
        RemoteDocument fileToSign = new RemoteDocument(sb.toString().getBytes(), "aFile.xml");

        // get data to sign
        GetDataToSignXMLElementsDTO prepareSignDto = new GetDataToSignXMLElementsDTO("XADES_LTA", fileToSign, clientSignatureParameters, targets, "ID");
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.GET_DATA_TO_SIGN_XADES_MDOC_URL, prepareSignDto, DataToSignDTO.class);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignXMLElementsDTO signDto = new SignXMLElementsDTO("XADES_LTA", fileToSign, clientSignatureParameters, targets, signatureValue.getValue(), "ID");
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.SIGN_DOCUMENT_XADES_MDOC_URL, signDto, RemoteDocument.class);
        assertNotNull(signedDocument);
    }
*/
}
