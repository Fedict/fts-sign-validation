package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.PdfSignatureProfile;
import com.bosa.signandvalidation.model.TokenSignInput;

import com.fasterxml.jackson.databind.ObjectMapper;
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

import static com.bosa.signandvalidation.service.PdfVisibleSignatureService.DEFAULT_STRING;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;

import java.awt.image.BufferedImage;
import java.io.*;
import java.util.Date;

@ExtendWith(MockitoExtension.class)
public class PdfVisibleSignatureServiceTest {

    private static int PIXEL_TO_IGNORE = 0xFFFFAEC9;
    private static int INVALID_PIXEL = 0xFFFF0000;
    private static final String THE_BUCKET = "THE_BUCKET";

    @Mock
    private StorageService storageService;

    private static final RemoteCertificate cert = CertInfoTest.getTomTestCertificate();
    static final String RESOURCE_PATH = "src/test/resources/";
    public static final File resourcesFile = new File(RESOURCE_PATH);
    public static final File pdfFile = new File(RESOURCE_PATH, "sample.pdf");
    public static final File pspTestFolder = new File(RESOURCE_PATH, "testPSPs");
    private static final File pspImagesFolder = new File(RESOURCE_PATH, "PSPImages");
    private static byte photoBytes[];
    private static byte pdfFileBytes[];

    @BeforeAll
    private static void init() throws IOException {
        photoBytes = Utils.toByteArray(new FileInputStream(RESOURCE_PATH + "photo.png"));
        pdfFileBytes = Utils.toByteArray(new FileInputStream(pdfFile));
        System.setProperty(PdfVisibleSignatureService.FONTS_PATH_PROPERTY, RESOURCE_PATH + "fonts");
    }

    @Test
    public void testV1RenderSignatureWithPsp() throws Exception {
        for (File f : pspTestFolder.listFiles()) {
            int posExt = f.getName().lastIndexOf("V1.psp");
            if (posExt >= 1) {
                byte[] pspFileBytes = Utils.toByteArray(new FileInputStream(f));
                String fileNameNoExt = f.getName().substring(0, posExt);

                RemoteSignatureParameters params = new RemoteSignatureParameters();
                params.getBLevelParams().setSigningDate(new Date(1657185646000L));
                params.setSigningCertificate(cert);
                RemoteDocument doc = new RemoteDocument(pdfFileBytes, "A.pdf");
                TokenSignInput input = new TokenSignInput();
                input.setPspFilePath(f.getPath());
                Mockito.reset(storageService);
                Mockito.when(storageService.getFileAsBytes(eq(THE_BUCKET), eq(f.getPath()), eq(false))).thenReturn(pspFileBytes);
                input.setSignLanguage(fileNameNoExt.substring(0, 2));
                String defaultCoordinates = (new ObjectMapper()).readValue(new String(pspFileBytes), PdfSignatureProfile.class).defaultCoordinates;
                input.setPsfC(defaultCoordinates == null ? "1,10,10,200,150" : DEFAULT_STRING);
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
        File imageFile = new File(pspImagesFolder, expectedFileName + ".png");

        System.out.println("Expected image file : " + imageFile.getPath());

        // If expected image not yet generated, create it in the resource folder
        if (!imageFile.exists()) new InMemoryDocument(actualBytes).save(imageFile.getPath());

        BufferedImage expectedImage = ImageIO.read(imageFile);
        BufferedImage actualImage = ImageIO.read(new ByteArrayInputStream(actualBytes));

        int differentPixelsCount = countMismatchedPixels(actualImage, expectedImage);
        if (differentPixelsCount == 0) return;

        // In case of image size or pixel mismatch, save actual image for quicker analysis
        imageFile = new File(pspImagesFolder, expectedFileName + "_ACTUAL.png");
        new InMemoryDocument(actualBytes).save(imageFile.getPath());

        if (differentPixelsCount < 0) {
            fail(String.format("Image sizes mismatch: actual : %d x %d - expected : %d x %d\nActual Image is here : %s",
                    actualImage.getWidth(), actualImage.getHeight(), expectedImage.getWidth(), expectedImage.getHeight(), imageFile.getPath()));
        }

        // In case of pixel mismatch, save red painted image for quicker analysis
        imageFile = new File(pspImagesFolder, expectedFileName + "_INV_PIXELS.png");
        ImageIO.write(expectedImage, "png", imageFile);
        fail("Difference between expected image and rendered image. Image with red painted invalid pixels is here : " + imageFile.getPath());
    }

    public static int countMismatchedPixels(BufferedImage actualImage, BufferedImage expectedImage) throws IOException {

        int expectedImageWidth = expectedImage.getWidth();
        int expectedImageHeight = expectedImage.getHeight();

        if (actualImage.getWidth() != expectedImageWidth || actualImage.getHeight() != expectedImageHeight)  return -1;

        int mismatchedPixels = 0;
        for (int y = 0; y < expectedImageHeight; y++) {
            for (int x = 0; x < expectedImageWidth; x++) {
                int actualRGB = actualImage.getRGB(x, y);
                int expectedRGB = expectedImage.getRGB(x, y);
                if (expectedRGB != PIXEL_TO_IGNORE && actualRGB != expectedRGB) {
                    expectedImage.setRGB(x, y, INVALID_PIXEL);
                    mismatchedPixels++;
                }
            }
        }
        return mismatchedPixels;
    }
}