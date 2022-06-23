package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.TokenSignInput;

import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureImageParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;

import java.io.File;
import java.io.FileInputStream;
import java.util.*;

@ExtendWith(MockitoExtension.class)
public class PdfVisibleSignatureServiceTest {
    private static final String THE_BUCKET = "THE_BUCKET";
    private static final Integer IMG_DPI = 400;

    @Mock
    private StorageService storageService;

    @Test
    public void testRenderSignature() throws Exception {

        PdfVisibleSignatureService srv = new PdfVisibleSignatureService(storageService);

        RemoteCertificate cert = CertInfoTest.getTomTestCertificate();
        byte photo[] = Utils.toByteArray(new FileInputStream("src/test/resources/photo.png"));
        byte pdfFile[] = Utils.toByteArray(new FileInputStream("src/test/resources/mini.pdf"));

        File testFolder = new File("src/test/resources/imageTests");
        for(File f : testFolder.listFiles()) {
            String fileName = f.getName();
            if (!fileName.endsWith(".psp")) continue;

            System.out.println("File : " + f.getPath());
            RemoteSignatureParameters params = new RemoteSignatureParameters();
            params.setSigningCertificate(cert);
            RemoteDocument doc = new RemoteDocument(pdfFile, "A.pdf");
            TokenSignInput input = new TokenSignInput();
            input.setPspFilePath(f.getPath());
            Mockito.reset(storageService);
            Mockito.when(storageService.getFileAsBytes(eq(THE_BUCKET), eq(f.getPath()), eq(false))).thenReturn(Utils.toByteArray(new FileInputStream(f)));
            input.setSignLanguage(fileName.substring(0, 2));
            input.setPsfC("2,20,20,300,150");
            srv.checkAndFillParams(params, doc, input, THE_BUCKET, fileName.charAt(2) == 'T' ? photo : null);

            RemoteSignatureImageParameters sigImgParams = params.getImageParameters();
            byte actualBytes[] = sigImgParams.getImage().getBytes();

            File png = new File(testFolder, "_" + fileName.substring(0, fileName.length() - 3) + "png");
            if (!png.exists()) new InMemoryDocument(actualBytes).save(png.getPath());

            byte expectedBytes[] = Utils.toByteArray(new FileInputStream(png));

            assertTrue(Arrays.equals(expectedBytes, actualBytes));
            assertEquals(IMG_DPI, sigImgParams.getDpi());
        }
    }
}

/*
    private VisualSignatureAlignmentHorizontal alignmentHorizontal;
        NONE,
        LEFT,
        CENTER,
        RIGHT;

    private VisualSignatureAlignmentVertical alignmentVertical;
        NONE,
        TOP,
        MIDDLE,
        BOTTOM;

    private ImageScaling imageScaling;
        STRETCH,
        ZOOM_AND_CENTER,
        CENTER;

    private RemoteColor backgroundColor;
        private Integer red;
        private Integer green;
        private Integer blue;
        private Integer alpha;

    private Integer dpi;
    private RemoteDocument image;
    private VisualSignatureRotation rotation;
        NONE,
        AUTOMATIC,
        ROTATE_90,
        ROTATE_180,
        ROTATE_270;

    private RemoteSignatureFieldParameters fieldParameters;
        private String fieldId;
        private Float originX;
        private Float originY;
        private Float width;
        private Float height;
        private Integer page;


    private RemoteSignatureImageTextParameters textParameters;
        private RemoteColor backgroundColor;
        private RemoteDocument font;
        private TextWrapping textWrapping;
            FILL_BOX,
            FILL_BOX_AND_LINEBREAK,
            FONT_BASED;

        private Float padding;
        private SignerTextHorizontalAlignment signerTextHorizontalAlignment;
            LEFT,
            CENTER,
            RIGHT;

        private SignerTextVerticalAlignment signerTextVerticalAlignment;
            TOP,
            MIDDLE,
            BOTTOM;

        private SignerTextPosition signerTextPosition;
            TOP,
            BOTTOM,
            RIGHT,
            LEFT;

        private Integer size;
        private String text;
        private RemoteColor textColor;

    private Integer zoom;
 */
