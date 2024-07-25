package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.*;
import com.bosa.signandvalidation.service.RemoteSigningInterface;
import com.bosa.signandvalidation.service.StorageService;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.ResponseEntity;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@SpringBootTest
public class SigningControllerRemoteTest {
    private static final String CODE = "theCode";
    private static final String SAD = "theSAD";
    private static final String TOKEN = "theToken";
    private static final String BUCKET = "theBucket";
    private static final String OUT_PREFIX = "OUT_";

    private static final String JSON_TOKEN = "{\"createTime\":" + System.currentTimeMillis() + ",\"signingType\":\"Standard\",\"bucket\":\"" + BUCKET + "\",\"signTimeout\":9999,\"tokenTimeout\":18000," +
        "\"requestDocumentReadConfirm\":false,\"previewDocuments\":true,\"selectDocuments\":false,\"noSkipErrors\":false,\"pdfSignProfile\":\"PADES_1\"," +
        "\"inputs\":[" +
            "{\"filePath\":\"file 0.pdf\",\"psfNWidth\":0.0,\"psfNHeight\":0.0,\"psfP\":false,\"invisible\":false}," +
            "{\"filePath\":\"file 1.pdf\",\"psfNWidth\":200.0,\"psfNHeight\":100.0,\"psfP\":false,\"invisible\":false}," +
            "{\"filePath\":\"file 2.pdf\",\"psfNWidth\":0.0,\"psfNHeight\":0.0,\"psfC\":\"1,100,100,200,300\",\"psfP\":false,\"invisible\":true}," +
            "{\"filePath\":\"file 3.pdf\",\"psfNWidth\":0.0,\"psfNHeight\":0.0,\"psfP\":false,\"invisible\":false}" +
        "],\"outDownload\":false,\"outPathPrefix\":\"" + OUT_PREFIX + "\"}";

    @MockBean
    private StorageService storageService;

    @Autowired
    private SigningController sc;

    private static RemoteSigningInterface testRemoteSigningService = new RemoteSigningInterface() {
        private Pkcs12SignatureToken token;
        private DSSPrivateKeyEntry dssPrivateKeyEntry;

        @Override
        public String getSadFromCode(String code) { return CODE.equals(code) ? SAD : null; }
        @Override
        public List<RemoteCertificate> getCertificatesFromSad(String sad) {
            List<RemoteCertificate> chain = new ArrayList<>();
            if (SAD.equals(sad)) {
                try {
                    token = new Pkcs12SignatureToken(
                            Files.newInputStream(Paths.get("src/test/resources/citizen_nonrep.p12")),
                            new KeyStore.PasswordProtection("123456".toCharArray())
                    );
                    List<DSSPrivateKeyEntry> keys = token.getKeys();
                    dssPrivateKeyEntry = keys.get(0);
                    chain.add(new RemoteCertificate(dssPrivateKeyEntry.getCertificate().getEncoded()));
                    for (CertificateToken certToken : dssPrivateKeyEntry.getCertificateChain()) {
                        chain.add(new RemoteCertificate(certToken.getEncoded()));
                    }
                } catch (Exception e) {}
            }
            return chain;
        }
        @Override
        public byte[][] signDigests(String sad, DataToSignDTO[] dto) {
            byte [][] digests = new byte[dto.length][];
            for(int i = 0; i < dto.length; i++) {
                Digest digest = new Digest(dto[i].getDigestAlgorithm(), dto[i].getDigest());
                digests[i] = token.signDigest(digest, dssPrivateKeyEntry).getValue();
            }
            return digests;
        }
    };

    @Test
    public void testRemoteSigning() throws Exception {

        sc.setRemoteSigningService(testRemoteSigningService);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.pdf"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

        RemoteSignDocumentDTO dto = new RemoteSignDocumentDTO("PADES_1", TOKEN, CODE, "fr", null, "1,10,20,200,100", null, null, toSignDocument);
        RemoteDocument signedDocument = sc.remoteSignDocument(dto);

        assertNotNull(signedDocument);
    }

    @Test
    public void testMultipleRemoteSigning() throws Exception {
        int fileIds[] = { 0, 2, 3 };
        FileDocument fileToSign = new FileDocument(new File("src/test/resources/signed_visible_sigfields.pdf"));
        byte [] fileBytes = Utils.toByteArray(fileToSign.openStream());

        Mockito.when(storageService.getFileAsBytes(eq(null),eq("keys/" + TOKEN + ".json"), eq(false))).thenReturn(JSON_TOKEN.getBytes());

        for(int i = 0; i < 3; i++) {
            Mockito.when(storageService.getFileAsBytes(eq(BUCKET), eq("file " + fileIds[i] + ".pdf"), eq(true))).thenReturn(fileBytes);
        }

        sc.setRemoteSigningService(testRemoteSigningService);

        List<InputToSign> inputsToSign = new ArrayList<>();
        inputsToSign.add(new InputToSign(0, null, "1,10,20,200,100", false, "fr"));
        inputsToSign.add(new InputToSign(2, "signature_2", null, false, "nl"));
        inputsToSign.add(new InputToSign(3, null, null, false, "de"));
        RemoteSignDocumentsForTokenDTO dto = new RemoteSignDocumentsForTokenDTO(TOKEN, CODE, null, inputsToSign);
        ResponseEntity<RemoteDocument> result = sc.remoteSignDocumentsForToken(dto);

        assertNotNull(result);
        assertNull(result.getBody());

        for(int i = 0; i < 3; i++) {
            verify(storageService, times(1)).storeFile(eq(BUCKET), eq(OUT_PREFIX + "file " + fileIds[i] + ".pdf"), any());
            verify(storageService, times(1)).storeFile(eq(BUCKET), eq(OUT_PREFIX + "file " + fileIds[i] + ".pdf.validationreport.json"), any());
        }
    }
}
