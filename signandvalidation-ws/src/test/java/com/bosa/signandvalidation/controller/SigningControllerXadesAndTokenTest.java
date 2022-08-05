package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.*;
import com.bosa.signandvalidation.service.BosaRemoteDocumentValidationService;
import com.bosa.signandvalidation.service.ReportsService;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.bosa.signandvalidation.service.StorageService;
import com.bosa.signingconfigurator.model.PolicyParameters;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import lombok.AllArgsConstructor;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.http.MediaType.APPLICATION_PDF;
import static org.springframework.http.MediaType.APPLICATION_XML;

public class SigningControllerXadesAndTokenTest extends SigningControllerBaseTest {

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
        F1("root/aFile.xml", "1", APPLICATION_XML, "QSBUZXN0", "pinp.xslt", "XSLT1"),
        F2("bFile.xml", "deux", APPLICATION_XML, "QSBUZXN0", "pimp1.xslt", "XSLT2"),
        F3("test.pdf", "drie", APPLICATION_PDF, "QSBUZXN0", null, null),
        F4("dFile.pdf", "FOUR", APPLICATION_PDF, "QSBUZXN0", null, null);

        private final String name;
        private final String id;
        private final MediaType type;
        private final String data;
        private final String xslt;
        private final String xsltData;

        SignInput getXmlSignInput() { return new SignInput(name, id, xslt); }
        public static FileDef find(String name) {
            for (FileDef fd : values()) {
                String fdName = fd.name;
                int pos = fdName.lastIndexOf('/');
                fdName = pos == -1 ? fdName : fdName.substring(pos + 1);
                if (name.compareTo(fdName) == 0 || name.compareTo(fdName) == 0)
                    return fd;
            }
            return null;
        }
    }

    private static String unSignedXmlFile;

    @Test
    public void testSignCreateToken() throws Exception {
        Mockito.when(storageService.isValidAuth(any(),any())).thenReturn(true);
        Mockito.when(storageService.getFileAsStream(eq(THE_BUCKET),eq(MAIN_XSLT_FILE_NAME))).thenReturn(new ByteArrayInputStream(MAIN_XSLT_FILE.getBytes()));

        WSReportsDTO reportsDto = new WSReportsDTO();
        Mockito.when(validationService.validateDocument(any(),any(), any(), any())).thenReturn(reportsDto);
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

            unSignedXmlFile += "<" + FILE_XSLT_ELT + " FileName=\"" + lastOccurenceOf(fd.name, '/') + "\" MimeType=\"" + lastOccurenceOf(fd.name, '.') + "\" iD=\"" + fd.id + "\">" + fd.data + "</" + FILE_XSLT_ELT + ">";
        }
        unSignedXmlFile += "</" + ROOT_XSLT_ELT + ">";

        // Start testing
        GetTokenForDocumentsDTO gtfd = new GetTokenForDocumentsDTO(THE_BUCKET, "pwd", "XADES_B", inFiles, OUT_FILE_NAME);
        gtfd.setOutXsltPath(MAIN_XSLT_FILE_NAME);
        gtfd.setOutDownload(true);

        // Create XML to sign
        String token = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_TOKEN_FOR_DOCUMENTS, gtfd, String.class);
        System.out.println(token);

        // First call from UI to get a view of the various files to display
        DocumentMetadataDTO fift = this.restTemplate.getForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_METADATA_FOR_TOKEN + "?token=" + token, DocumentMetadataDTO.class);

        int inputIndex = 0;
        for(SignInputMetadata input : fift.getInputs()) {
            // Per file call to display content & XSLT
            ResponseEntity<byte[]> file = this.restTemplate.getForEntity(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_FILE_FOR_TOKEN + "/" + token + "/" + GetFileType.DOC + "/" + inputIndex, byte[].class);

            FileDef fd = FileDef.find(input.getFileName());
            assertEquals(new String(file.getBody()), fd.data);
            assertEquals(file.getHeaders().getContentType(), fd.type);

            if (input.isHasDisplayXslt()) {
                file = this.restTemplate.getForEntity(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_FILE_FOR_TOKEN + "/" + token + "/" + GetFileType.XSLT + "/" + inputIndex, byte[].class);

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
        GetDataToSignForTokenDTO dto = new GetDataToSignForTokenDTO(token, 0, csp);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_DATA_TO_SIGN_FOR_TOKEN, dto, DataToSignDTO.class);

        // Sign hash
        SignatureValue signatureValue = sigToken.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), sigToken.getKeys().get(0));

        // Sign file & return its content
        csp.setSigningDate(dataToSign.getSigningDate());
        SignDocumentForTokenDTO sdto = new SignDocumentForTokenDTO(token, 0, csp, signatureValue.getValue());
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.SIGN_DOCUMENT_FOR_TOKEN, sdto, RemoteDocument.class);

        assertNull(signedDocument);
    }

    private static String lastOccurenceOf(String name, char c) {
        int pos = name.lastIndexOf(c);
        return pos == -1 ? name : name.substring(pos + 1);
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
        for(SigningControllerXadesAndTokenTest.FileDef fDef : SigningControllerXadesAndTokenTest.FileDef.values()) {
            targets.add(new SignElement(fDef.id, fDef.type.toString()));
            sb.append("<file id=\"").append(fDef.id).append("\" name=\"").append(fDef.name).append("\">").append(fDef.data).append("</file>");
        }
        sb.append("</root>");
        System.out.println(sb);
        RemoteDocument fileToSign = new RemoteDocument(sb.toString().getBytes(), "aFile.xml");

        PolicyParameters policy = null;
        // TODO The current code needs access to a proxy to validate the Policies, therefore it can't run on the pipelines
//      policy = new PolicyParameters("http://signinfo.eda.just.fgov.be/SignaturePolicy/pdf/Notary/BE_Justice_Signature_Policy_Notary_eID_Hum_v0.10_202109_Fr.pdf", "policyDesc", DigestAlgorithm.SHA256);

        // get data to sign
        GetDataToSignXMLElementsDTO prepareSignDto = new GetDataToSignXMLElementsDTO("XADES_LTA", fileToSign, clientSignatureParameters, policy, targets);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_DATA_TO_SIGN_XADES_MULTI_DOC, prepareSignDto, DataToSignDTO.class);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignXMLElementsDTO signDto = new SignXMLElementsDTO("XADES_LTA", fileToSign, clientSignatureParameters, policy, targets, signatureValue.getValue());
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.SIGN_DOCUMENT_XADES_MULTI_DOC, signDto, RemoteDocument.class);
        assertNotNull(signedDocument);
    }
}
