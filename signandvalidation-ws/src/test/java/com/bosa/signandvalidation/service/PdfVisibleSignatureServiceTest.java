package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.PdfSignatureProfile;
import com.bosa.signandvalidation.model.TokenSignInput;

import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.jose4j.base64url.Base64;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.imageio.ImageIO;

import static com.bosa.signandvalidation.service.PdfVisibleSignatureService.DEFAULT_STRING;
import static org.junit.jupiter.api.Assertions.*;

import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Date;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@ExtendWith(MockitoExtension.class)
public class PdfVisibleSignatureServiceTest {

    private static final boolean isWindows = System.getProperty("os.name").startsWith("Windows");
    private static ByteArrayOutputStream newFilesBytes;
    private static ZipOutputStream newFilesZip;
    private static final String THE_BUCKET = "THE_BUCKET";

    @Mock
    private StorageService storageService;

    private static final RemoteCertificate cert = CertInfoTest.getTomTestCertificate();
    static final String RESOURCE_PATH = "src/test/resources/";
    public static final File resourcesFile = new File(RESOURCE_PATH);
    public static final File pdfFile = new File(RESOURCE_PATH, "sample.pdf");
    public static final File pspTestFolder = new File(RESOURCE_PATH, "testPSPs");
    private static final File pspImagesFolder = new File(RESOURCE_PATH, "PSPImages");
    private static final File pspImagesFolderWindows = new File(pspImagesFolder, "Windows");
    private static byte photoBytes[];

    @BeforeAll
    public static void init() throws IOException {
        photoBytes = Utils.toByteArray(Files.newInputStream(Paths.get(RESOURCE_PATH + "photo.png")));
        System.setProperty(PdfVisibleSignatureService.FONTS_PATH_PROPERTY, RESOURCE_PATH + "fonts");
        clearList();
    }
    @AfterAll
    public static void out() throws IOException {
        printNewPdfSignatureFiles();
    }

    public static void clearList() {
        if (isWindows) return;

        newFilesBytes = new ByteArrayOutputStream();
        newFilesZip = new ZipOutputStream(newFilesBytes);
    }

    public static void printNewPdfSignatureFiles() throws IOException {
        if (isWindows) return;

        newFilesZip.close();
        Logger logger = Logger.getLogger(PdfVisibleSignatureServiceTest.class.getName());
        logger.severe("Listing Base 64 Zip file of all new PDF signature Images");
        logger.severe(Base64.encode(newFilesBytes.toByteArray()));
    }

    @Test
    public void testV1RenderSignatureWithPsp() throws Exception {
        for (File f : pspTestFolder.listFiles()) {
            int posExt = f.getName().lastIndexOf("V1.psp");
            if (posExt >= 1) {
                byte[] pspFileBytes = Utils.toByteArray(Files.newInputStream(f.toPath()));
                String fileNameNoExt = f.getName().substring(0, posExt);

                RemoteSignatureParameters params = new RemoteSignatureParameters();
                params.getBLevelParams().setSigningDate(new Date(1657185646000L));
                params.setSigningCertificate(cert);
                ClientSignatureParameters clientSigParams = new ClientSignatureParameters();
                PdfSignatureProfile psp = (new ObjectMapper()).readValue(new String(pspFileBytes), PdfSignatureProfile.class);
                clientSigParams.setPsp(psp);
                clientSigParams.setPsfC(psp.defaultCoordinates == null ? "1,10,10,200,150" : DEFAULT_STRING);
                clientSigParams.setSignLanguage(fileNameNoExt.substring(0, 2));
                if (fileNameNoExt.charAt(2) == 'T') clientSigParams.setPhoto(photoBytes);
                new PdfVisibleSignatureService(storageService).checkAndFillParams(params, 0, 0, clientSigParams);

                compareImages(params.getImageParameters().getImage().getBytes(), fileNameNoExt);
            }
        }
    }

    @Test
    public void testV1RenderSignature() throws Exception {
        RemoteSignatureParameters params = new RemoteSignatureParameters();
        params.setSigningCertificate(cert);
        ClientSignatureParameters clientSigParams = new ClientSignatureParameters();
        clientSigParams.setSignLanguage("fr");
        clientSigParams.setPsfC("2,20,20,300,150");
        clientSigParams.setPhoto(photoBytes);
        new PdfVisibleSignatureService(storageService).checkAndFillParams(params, 0, 0, clientSigParams);

        compareImages(params.getImageParameters().getImage().getBytes(), "noPSP1");
    }

    public static void compareImages(byte[] actualBytes, String expectedFileName) throws IOException {

        File imageFile = new File(pspImagesFolder, expectedFileName + ".png");
        if (isWindows) {
            File windowsImageFile = new File(pspImagesFolderWindows, imageFile.getName());
            if (windowsImageFile.exists()) imageFile = windowsImageFile;
        }

        System.out.println("Expected image file : " + imageFile.getPath());

        // On CI/CD the platform differences create different images, in order to get a copy of them we print the B64
        // If expected image not yet generated, create it in the resource folder or print it in a stream that will be logged (On servers)
        if (!imageFile.exists()) {
            if (!isWindows) {
                newFilesZip.putNextEntry(new ZipEntry(imageFile.getName()));
                Utils.copy(new ByteArrayInputStream((actualBytes)), newFilesZip);
                return;
            } else {
                new InMemoryDocument(actualBytes).save(imageFile.getPath());
            }
        }

        BufferedImage expectedImage = ImageIO.read(imageFile);
        BufferedImage actualImage = ImageIO.read(new ByteArrayInputStream(actualBytes));

        int differentPixelsCount = countMismatchedPixels(actualImage, expectedImage);
        if (differentPixelsCount == 0) return;

        // In case of image size or pixel mismatch, save actual image for quicker analysis
        imageFile = new File(imageFile.getParent(), expectedFileName + "_ACTUAL.png");

        new InMemoryDocument(actualBytes).save(imageFile.getPath());

        if (differentPixelsCount < 0) {
            fail(String.format("Image sizes mismatch: actual : %d x %d - expected : %d x %d\nActual Image is here : %s",
                    actualImage.getWidth(), actualImage.getHeight(), expectedImage.getWidth(), expectedImage.getHeight(), imageFile.getPath()));
        }

        // In case of pixel mismatch, save red painted image for quicker analysis
        imageFile = new File(imageFile.getParent(), expectedFileName + "_INV_PIXELS.png");
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
                int PIXEL_TO_IGNORE = 0xFFFFAEC9;
                if (expectedRGB != PIXEL_TO_IGNORE && actualRGB != expectedRGB) {
                    int INVALID_PIXEL = 0xFFFF0000;
                    expectedImage.setRGB(x, y, INVALID_PIXEL);
                    mismatchedPixels++;
                }
            }
        }
        return mismatchedPixels;
    }
}
