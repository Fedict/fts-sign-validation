package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.*;
import com.bosa.signandvalidation.service.RemoteSigningInterface;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class SigningControllerRemoteTest {
    private static final String CODE = "theCode";
    private static final String SAD = "theSAD";

    @Autowired
    private SigningController sc;

    @Test
    public void testRemoteSigning() throws Exception {

        sc.setRemoteSigningService(new RemoteSigningInterface() {
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
                Digest digest = new Digest(dto[0].getDigestAlgorithm(), dto[0].getDigest());
                return new byte[][] {token.signDigest(digest, dssPrivateKeyEntry).getValue()};
            }
        });

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.pdf"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

        RemoteSignDocumentDTO dto = new RemoteSignDocumentDTO("PADES_1", "zeToken", CODE, "fr", null, "1,10,20,200,100", null, toSignDocument);
        RemoteDocument signedDocument = sc.remoteSignDocument(dto);

        assertNotNull(signedDocument);
    }
}
