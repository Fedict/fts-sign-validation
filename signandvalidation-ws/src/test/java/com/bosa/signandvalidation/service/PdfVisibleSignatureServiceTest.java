package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.TokenSignInput;

import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.imageio.ImageIO;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Date;

@ExtendWith(MockitoExtension.class)
public class PdfVisibleSignatureServiceTest {
    private static final String THE_BUCKET = "THE_BUCKET";
    private static final Integer IMG_DPI = 400;

    @Mock
    private StorageService storageService;

    private static final RemoteCertificate cert = CertInfoTest.getTomTestCertificate();
    private static final String resources = "src/test/resources/";
    private static final File testFolder = new File(resources + "imageTests");
    private static byte photo[];
    private static byte pdfFile[];

    @BeforeAll
    private static void init() throws IOException {
        photo = Utils.toByteArray(new FileInputStream(resources + "photo.png"));
        pdfFile = Utils.toByteArray(new FileInputStream(resources + "mini.pdf"));
    }

    @Test
    public void testRenderSignatureWithPsp() throws Exception {

        for(File f : testFolder.listFiles()) {
            String fileNameBits[] = f.getName().split("\\.");
            if ("psp".compareTo(fileNameBits[1]) != 0) continue;

            RemoteSignatureParameters params = new RemoteSignatureParameters();
            params.getBLevelParams().setSigningDate(new Date(1655970685000L));
            params.setSigningCertificate(cert);
            RemoteDocument doc = new RemoteDocument(pdfFile, "A.pdf");
            TokenSignInput input = new TokenSignInput();
            input.setPspFilePath(f.getPath());
            Mockito.reset(storageService);
            Mockito.when(storageService.getFileAsBytes(eq(THE_BUCKET), eq(f.getPath()), eq(false))).thenReturn(Utils.toByteArray(new FileInputStream(f)));
            input.setSignLanguage(fileNameBits[0].substring(0, 2));
            input.setPsfC("2,20,20,300,150");
            new PdfVisibleSignatureService(storageService).checkAndFillParams(params, doc, input, THE_BUCKET, fileNameBits[0].charAt(2) == 'T' ? photo : null);

            compareImages(params.getImageParameters().getImage().getBytes(), fileNameBits[0]);
        }
    }

    @Test
    public void testRenderSignature() throws Exception {
        RemoteSignatureParameters params = new RemoteSignatureParameters();
        params.setSigningCertificate(cert);
        RemoteDocument doc = new RemoteDocument(pdfFile, "A.pdf");
        TokenSignInput input = new TokenSignInput();
        input.setSignLanguage("fr");
        input.setPsfC("2,20,20,300,150");
        new PdfVisibleSignatureService(storageService).checkAndFillParams(params, doc, input, THE_BUCKET, photo);

        compareImages(params.getImageParameters().getImage().getBytes(), "noPSP1");
    }

    private void compareImages(byte[] actualBytes, String expectedFileName) throws IOException {
        expectedFileName = "_" + expectedFileName;
        File imageFile = new File(testFolder, expectedFileName + ".png");

        System.out.println("Expected image file : " + imageFile.getPath());

        // If expected image not yet generated, create it in the resource folder
        if (!imageFile.exists()) new InMemoryDocument(actualBytes).save(imageFile.getPath());

        BufferedImage expectedImage = ImageIO.read(imageFile);
        BufferedImage actualImage = ImageIO.read(new ByteArrayInputStream(actualBytes));

        int expectedImageWidth = expectedImage.getWidth();
        int expectedImageHeight = expectedImage.getHeight();

        int mismatchPixels = 0;
        if (actualImage.getWidth() == expectedImageWidth && actualImage.getHeight() == expectedImageHeight) {
            for (int y = 0; y < expectedImageHeight; y++) {
                for (int x = 0; x < expectedImageWidth; x++) {
                    if (actualImage.getRGB(x, y) != expectedImage.getRGB(x, y)) {
                        expectedImage.setRGB(x, y, 0xFF0000);
                        mismatchPixels++;
                    }
                }
            }
            if (mismatchPixels == 0) return;
        }

        // In case of image size or pixel mismatch, save actual image for quicker analysis
        imageFile = new File(testFolder, expectedFileName + "_ACTUAL.png");
        new InMemoryDocument(actualBytes).save(imageFile.getPath());

        if (mismatchPixels == 0) {
            fail(String.format("Image sizes mismatch: actual : %d x %d - expected : %d x %d\nActual Image is here : %s",
                    actualImage.getWidth(), actualImage.getHeight(), expectedImageWidth, expectedImageHeight, imageFile.getPath()));
        }

        // In case of pixel mismatch, save red painted image for quicker analysis
        imageFile = new File(testFolder, expectedFileName + "_INV_PIXELS.png");
        ImageIO.write(expectedImage, "png", imageFile);
        fail("Difference between expected image and rendered image. Image with red painted invalid pixels is here : " + imageFile.getPath());
    }
}
