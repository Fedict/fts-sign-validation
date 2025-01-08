package com.bosa.signandvalidation;

import com.bosa.signandvalidation.exceptions.Utils;
import com.bosa.signandvalidation.model.TrustSources;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static com.bosa.signandvalidation.exceptions.Utils.getGetExtraTrustFile;
import static com.bosa.signandvalidation.service.PdfVisibleSignatureServiceTest.pspTestFolder;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class CheckTrusts {
    // Test if all certificates from the extra trusts are readable.
    @Test
    public void testExistingTrusts() throws IllegalAccessException, IOException {

        char[] PASSWORD_CHARS = "SILLY_PASSWORD".toCharArray();

        File trustsFolder = new File("src/main/resources/trusts");
        InputStream fis = null;
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            for (File f : trustsFolder.listFiles()) {
                System.out.println("Certificate : " + f.getName());
                if (f.getName().endsWith(".crt")) {
                    fis = Files.newInputStream(f.toPath());
                    byte[] certBytes = fis.readAllBytes();
                    certBytes = Base64.getMimeDecoder().decode(certBytes);

                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                    keyStore.setCertificateEntry(f.getName(), cert);
                }
            }
            ByteArrayOutputStream baos = new ByteArrayOutputStream(1000);

            keyStore.store(baos, PASSWORD_CHARS);
            InputStream keyStoreStream = new ByteArrayInputStream(baos.toByteArray());
            KeyStoreCertificateSource keystoreCrtSrc = new KeyStoreCertificateSource(keyStoreStream, "PKCS12", PASSWORD_CHARS);

            // If some certs in the folder are the same they will be removed from the keystore
            assertEquals(4, keystoreCrtSrc.getCertificates().size());

        } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } finally {
            if (fis != null) fis.close();
        }
    }
}
