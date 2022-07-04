package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.controller.SigningController;
import com.bosa.signandvalidation.controller.SigningControllerBaseTest;
import com.bosa.signandvalidation.model.*;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import org.apache.pdfbox.contentstream.PDFGraphicsStreamEngine;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.graphics.image.PDImage;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceEntry;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.util.Matrix;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;

import javax.imageio.ImageIO;
import java.awt.geom.Point2D;
import java.awt.image.BufferedImage;
import java.io.*;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.bosa.signandvalidation.service.PdfVisibleSignatureServiceTest.*;
import static org.mockito.ArgumentMatchers.*;

public class PdfVisibleSignatureTokenTest extends SigningControllerBaseTest {
    @MockBean
    private StorageService storageService;

    public static final File pspTestFolder = new File(resources + "imageTestsV2");

    private static byte photoBytes[];

    @Test
    public void testExtract() throws Exception {

        PDDocument document = PDDocument.load(Utils.toByteArray(new FileInputStream(resources + "imageTestsV2/deF_V2signature1.pdf")));
        extractPageAnnotationImages(document, "image-%s-%s%s.%s");
    }

    @Test
    public void testV2RenderSignaturesWithPsp() throws Exception {
        photoBytes = Utils.toByteArray(new FileInputStream("src/test/resources/photo.png"));

        for (File f : pspTestFolder.listFiles()) {
            if (f.getName().endsWith(".psp")) testRenderSignature(f);
        }
    }

    private void testRenderSignature(File pspFile) throws IOException {
        Mockito.reset(storageService);
        Mockito.when(storageService.isValidAuth(any(), any())).thenReturn(true);

        byte[] pdfFileBytes = Utils.toByteArray(new FileInputStream(pdfFile));
        Mockito.when(storageService.getFileAsBytes(any(), eq("sample.pdf"), anyBoolean())).thenReturn(pdfFileBytes);

        String pspFileName = pspFile.getName();

        byte photo[] = pspFileName.charAt(2) == 'T' ? photoBytes : null;
        byte[] fileBytes = Utils.toByteArray(new FileInputStream(pspFile));
        Mockito.when(storageService.getFileAsBytes(anyString(), eq(pspFileName), anyBoolean())).thenReturn(fileBytes);

        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);
        clientSignatureParameters.setPhoto(photo);

        // get token from file
        GetTokenForDocumentDTO getTokenDTO = new GetTokenForDocumentDTO();
        getTokenDTO.setProf("PADES_B");
        getTokenDTO.setLang(pspFileName.substring(0, 2));
        getTokenDTO.setName("THE_BUCKET");
        getTokenDTO.setPsfC("1,100,100,200,100");
        getTokenDTO.setPsfP(photo == null ? "false" : "true");
        getTokenDTO.setPsp(pspFileName);
        getTokenDTO.setIn("sample.pdf");
        getTokenDTO.setSignTimeout(1000);
        getTokenDTO.setOut("out");
        String tokenStr = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_TOKEN_FOR_DOCUMENT, getTokenDTO, String.class);

        // get data to sign
        GetDataToSignForTokenDTO dataToSignDTO = new GetDataToSignForTokenDTO(tokenStr, "non, rien !", clientSignatureParameters);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_DATA_TO_SIGN_FOR_TOKEN, dataToSignDTO, DataToSignDTO.class);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentForTokenDTO signDocumentDTO = new SignDocumentForTokenDTO(tokenStr, clientSignatureParameters, signatureValue.getValue());
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.SIGN_DOCUMENT_FOR_TOKEN, signDocumentDTO, RemoteDocument.class);

/*
        File pdf = new File(pspTestFolder, pspFileName.substring(0, pspFileName.length() - 4) + ".pdf");
        new InMemoryDocument(signedDocument.getBytes()).save(pdf.getPath());
 */

        BufferedImage signature = getSignatureImage(signedDocument.getBytes());
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        ImageIO.write(signature, "png", outStream);
        PdfVisibleSignatureServiceTest.compareImages(outStream.toByteArray(), pspFileName.substring(0, pspFileName.length() - 4));
    }

    private BufferedImage getSignatureImage(byte[] docBytes) throws IOException
    {
        PDDocument document = PDDocument.load(docBytes);
        extractPageAnnotationImages(document, "image-%s-%s%s.%s");
        PDPage pdPage = document.getPages().get(0);
        Map<String, PDAppearanceStream> allStreams = new HashMap<>();
        PDAnnotation pdAnnotation = pdPage.getAnnotations().get(0);
        PDAppearanceDictionary appearancesDictionary = pdAnnotation.getAppearance();
        PDAppearanceEntry apparence = appearancesDictionary.getNormalAppearance();

        final BufferedImage[] outImages = {null};
        PDFGraphicsStreamEngine pdfGraphicsStreamEngine = new PDFGraphicsStreamEngine(pdPage)
        {
            @Override
            public void processPage(PDPage page) throws IOException {
                processChildStream(apparence.getAppearanceStream(), pdPage);
            }

            @Override
            public void drawImage(PDImage pdImage) throws IOException
            {
                if (pdImage instanceof PDImageXObject)
                {
                    Matrix ctm = getGraphicsState().getCurrentTransformationMatrix();
                    String flips = "";
                    if (ctm.getScaleX() < 0)
                        flips += "h";
                    if (ctm.getScaleY() < 0)
                        flips += "v";
                    if (flips.length() > 0)
                        flips = "-" + flips;
                    outImages[0] = ((PDImageXObject)pdImage).getImage();
                }
            }

            @Override
            public void appendRectangle(Point2D p0, Point2D p1, Point2D p2, Point2D p3) throws IOException { }

            @Override
            public void clip(int windingRule) throws IOException { }

            @Override
            public void moveTo(float x, float y) throws IOException {  }

            @Override
            public void lineTo(float x, float y) throws IOException { }

            @Override
            public void curveTo(float x1, float y1, float x2, float y2, float x3, float y3) throws IOException {  }

            @Override
            public Point2D getCurrentPoint() throws IOException { return new Point2D.Float(); }

            @Override
            public void closePath() throws IOException { }

            @Override
            public void endPath() throws IOException { }

            @Override
            public void strokePath() throws IOException { }

            @Override
            public void fillPath(int windingRule) throws IOException { }

            @Override
            public void fillAndStrokePath(int windingRule) throws IOException { }

            @Override
            public void shadingFill(COSName shadingName) throws IOException { }
        };
        pdfGraphicsStreamEngine.processPage(pdPage);

        return outImages[0];
    }


    void extractPageAnnotationImages(PDDocument document, String fileNameFormat) throws IOException
    {
        int page = 1;
        for (final PDPage pdPage : document.getPages())
        {
            final int currentPage = page;
            Map<String, PDAppearanceStream> allStreams = new HashMap<>();
            int annot = 1;
            for (PDAnnotation pdAnnotation  : pdPage.getAnnotations()) {
                System.out.println("Annot " + annot + " - " + pdAnnotation.getAnnotationFlags() + " - " + pdAnnotation.getSubtype() + " - " + pdAnnotation.getClass().getName());
                PDAppearanceDictionary appearancesDictionary = pdAnnotation.getAppearance();
                Map<String, PDAppearanceEntry> dictsOrStreams = new HashMap();
                dictsOrStreams.put("Normal", appearancesDictionary.getNormalAppearance());
/*
                dictsOrStreams.put("Rollover", appearancesDictionary.getRolloverAppearance());
                dictsOrStreams.put("Normal", appearancesDictionary.getNormalAppearance());
 */
                for (Map.Entry<String, PDAppearanceEntry> entry : dictsOrStreams.entrySet()) {
                    if (entry.getValue().isStream()) {
                        System.out.println("Str " + annot + " - " + pdAnnotation) ;
                        allStreams.put(String.format("%d-%s", annot, entry.getKey()), entry.getValue().getAppearanceStream());
                    } else {
                        for (Map.Entry<COSName, PDAppearanceStream> subEntry : entry.getValue().getSubDictionary().entrySet()) {
                            System.out.println("SubStr " + annot + " - " + pdAnnotation) ;
                            allStreams.put(String.format("%d-%s.%s", annot, entry.getKey(), subEntry.getKey().getName()), subEntry.getValue());
                        }
                    }
                }
                annot++;
            }

            PDFGraphicsStreamEngine pdfGraphicsStreamEngine = new PDFGraphicsStreamEngine(pdPage)
            {
                String current = null;

                @Override
                public void processPage(PDPage page) throws IOException {
                    for (Map.Entry<String,PDAppearanceStream> entry : allStreams.entrySet()) {
                        current = entry.getKey();
                        System.out.println("Annot " + entry.getKey() + " - " + entry.getValue()) ;
                        processChildStream(entry.getValue(), pdPage);
                    }
                }

                @Override
                public void drawImage(PDImage pdImage) throws IOException
                {
                    System.out.println("Img " + pdImage.getSuffix() + " - " + pdImage.getHeight() + " - " + pdImage.getWidth());
                    if (pdImage instanceof PDImageXObject)
                    {
                        Matrix ctm = getGraphicsState().getCurrentTransformationMatrix();
                        String flips = "";
                        if (ctm.getScaleX() < 0)
                            flips += "h";
                        if (ctm.getScaleY() < 0)
                            flips += "v";
                        if (flips.length() > 0)
                            flips = "-" + flips;
                        PDImageXObject image = (PDImageXObject)pdImage;
                        File file = new File(String.format(fileNameFormat, currentPage, current, flips, image.getSuffix()));
                        ImageIO.write(image.getImage(), image.getSuffix(), new FileOutputStream(file));
                    }
                }

                @Override
                public void appendRectangle(Point2D p0, Point2D p1, Point2D p2, Point2D p3) throws IOException { }

                @Override
                public void clip(int windingRule) throws IOException { }

                @Override
                public void moveTo(float x, float y) throws IOException {  }

                @Override
                public void lineTo(float x, float y) throws IOException { }

                @Override
                public void curveTo(float x1, float y1, float x2, float y2, float x3, float y3) throws IOException {  }

                @Override
                public Point2D getCurrentPoint() throws IOException { return new Point2D.Float(); }

                @Override
                public void closePath() throws IOException { }

                @Override
                public void endPath() throws IOException { }

                @Override
                public void strokePath() throws IOException { }

                @Override
                public void fillPath(int windingRule) throws IOException { }

                @Override
                public void fillAndStrokePath(int windingRule) throws IOException { }

                @Override
                public void shadingFill(COSName shadingName) throws IOException { }
            };
            pdfGraphicsStreamEngine.processPage(pdPage);
            page++;
        }
    }
}
