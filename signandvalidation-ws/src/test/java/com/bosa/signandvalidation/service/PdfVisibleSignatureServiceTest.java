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
import java.io.*;

@ExtendWith(MockitoExtension.class)
public class PdfVisibleSignatureServiceTest {

    private static int PIXEL_TO_IGNORE = 0xFFFFAEC9;
    private static int INVALID_PIXEL = 0xFFFF0000;
    private static final String THE_BUCKET = "THE_BUCKET";

    @Mock
    private StorageService storageService;

    private static final RemoteCertificate cert = CertInfoTest.getTomTestCertificate();
    static final String resources = "src/test/resources/";
    private static final File pspTestFolder = new File(resources + "imageTests");
    public static final File pdfFile = new File(resources + "sample.pdf");
    private static byte photoBytes[];
    private static byte pdfFileBytes[];

    @BeforeAll
    private static void init() throws IOException {
        photoBytes = Utils.toByteArray(new FileInputStream(resources + "photo.png"));
        pdfFileBytes = Utils.toByteArray(new FileInputStream(pdfFile));
    }

    @Test
    public void testV1RenderSignatureWithPsp() throws Exception {
        for (File f : pspTestFolder.listFiles()) {
            int posExt = f.getName().lastIndexOf(".psp");
            if (posExt >= 1) {
                byte[] pspBytes = Utils.toByteArray(new FileInputStream(f));
                String fileNameNoExt = f.getName().substring(0, posExt);

                RemoteSignatureParameters params = new RemoteSignatureParameters();
                params.setSigningCertificate(cert);
                RemoteDocument doc = new RemoteDocument(pdfFileBytes, "A.pdf");
                TokenSignInput input = new TokenSignInput();
                input.setPspFilePath(f.getPath());
                Mockito.reset(storageService);
                Mockito.when(storageService.getFileAsBytes(eq(THE_BUCKET), eq(f.getPath()), eq(false))).thenReturn(pspBytes);
                input.setSignLanguage(fileNameNoExt.substring(0, 2));
                input.setPsfC("2,20,20,300,150");
                new PdfVisibleSignatureService(storageService).checkAndFillParams(params, doc, input, THE_BUCKET, fileNameNoExt.charAt(2) == 'T' ? photoBytes : null);

                compareImages(params.getImageParameters().getImage().getBytes(), fileNameNoExt);
            }
        }
    }

    @Test
    public void testV1RenderSignature() throws Exception {
        RemoteSignatureParameters params = new RemoteSignatureParameters();
        params.setSigningCertificate(cert);
        RemoteDocument doc = new RemoteDocument(pdfFileBytes, "A.pdf");
        TokenSignInput input = new TokenSignInput();
        input.setSignLanguage("fr");
        input.setPsfC("2,20,20,300,150");
        new PdfVisibleSignatureService(storageService).checkAndFillParams(params, doc, input, THE_BUCKET, photoBytes);

        compareImages(params.getImageParameters().getImage().getBytes(), "noPSP1");
    }

    public static void compareImages(byte[] actualBytes, String expectedFileName) throws IOException {

        expectedFileName = "_" + expectedFileName;
        File imageFile = new File(pspTestFolder, expectedFileName + ".png");

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
                    int actualRGB = actualImage.getRGB(x, y);
                    int expectedRGB = expectedImage.getRGB(x, y);
                    if (expectedRGB != PIXEL_TO_IGNORE && actualRGB != expectedRGB) {
                        expectedImage.setRGB(x, y, INVALID_PIXEL);
                        mismatchPixels++;
                    }
                }
            }
            if (mismatchPixels == 0) return;
        }

        // In case of image size or pixel mismatch, save actual image for quicker analysis
        imageFile = new File(pspTestFolder, expectedFileName + "_ACTUAL.png");
        new InMemoryDocument(actualBytes).save(imageFile.getPath());

        if (mismatchPixels == 0) {
            fail(String.format("Image sizes mismatch: actual : %d x %d - expected : %d x %d\nActual Image is here : %s",
                    actualImage.getWidth(), actualImage.getHeight(), expectedImageWidth, expectedImageHeight, imageFile.getPath()));
        }

        // In case of pixel mismatch, save red painted image for quicker analysis
        imageFile = new File(pspTestFolder, expectedFileName + "_INV_PIXELS.png");
        ImageIO.write(expectedImage, "png", imageFile);
        fail("Difference between expected image and rendered image. Image with red painted invalid pixels is here : " + imageFile.getPath());
    }
}