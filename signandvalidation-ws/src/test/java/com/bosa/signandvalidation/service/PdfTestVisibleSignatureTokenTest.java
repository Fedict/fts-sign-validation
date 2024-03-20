package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.controller.SigningController;
import com.bosa.signandvalidation.controller.SigningControllerBaseTest;
import com.bosa.signandvalidation.model.*;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.security.KeyStore;
import java.util.List;

import static com.bosa.signandvalidation.service.PdfVisibleSignatureService.DEFAULT_STRING;
import static com.bosa.signandvalidation.service.PdfVisibleSignatureServiceTest.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doAnswer;

public class PdfTestVisibleSignatureTokenTest extends SigningControllerBaseTest {

    private static final String DEFAULT_COORDINATES = "1,0,0,200,150";
    private static final String THE_BUCKET = "THE_BUCKET";
    private static final String THE_OUT_FILENAME = "out";

    @MockBean
    private StorageService storageService;

    private static byte photoBytes[];

    @BeforeAll
    static void init() throws IOException {
        photoBytes = Utils.toByteArray(new FileInputStream(RESOURCE_PATH + "photo.png"));
        System.setProperty(PdfVisibleSignatureService.FONTS_PATH_PROPERTY, RESOURCE_PATH + "fonts");
        PdfVisibleSignatureServiceTest.clearList();
    }
    @AfterAll
    public static void out() throws IOException {
        PdfVisibleSignatureServiceTest.printNewPdfSignatureFiles();
    }

    @Test
    public void testRenderSignaturesWithAllPspV1() throws Exception {
        testRenderSignaturesWithAllPsp("V1", false);
    }

    @Test
    public void testRenderSignaturesWithAllPspV1ForcedToV2() throws Exception {
        testRenderSignaturesWithAllPsp("V1", true);
    }

    @Test
    public void testRenderSignaturesWithAllPspV2() throws Exception {
        testRenderSignaturesWithAllPsp("V2", false);
    }

    private void testRenderSignaturesWithAllPsp(String filter, boolean forceV2) throws Exception {
        for (File f : pspTestFolder.listFiles()) {
            if (f.getName().endsWith(filter + ".psp")) testRenderSignature(f, forceV2);
        }
    }

    private void testRenderSignature(File pspFile, boolean forceV2) throws IOException {
            Mockito.reset(storageService);
            Mockito.when(storageService.isValidAuth(any(), any())).thenReturn(true);

            byte[] pdfFileBytes = Utils.toByteArray(new FileInputStream(pdfFile));
            Mockito.when(storageService.getFileAsBytes(any(), eq("sample.pdf"), anyBoolean())).thenReturn(pdfFileBytes);

            String pspFileName = pspFile.getName();

            byte photo[] = pspFileName.charAt(2) == 'T' ? photoBytes : null;
            byte[] pspFileBytes = Utils.toByteArray(new FileInputStream(pspFile));
            if (forceV2) {
                ObjectMapper om = new ObjectMapper();
                PdfSignatureProfile psp = om.readValue(new String(pspFileBytes), PdfSignatureProfile.class);
                psp.version = 2;
                pspFileBytes = om.writeValueAsString(psp).getBytes();
            }
            final String pspFileString = new String(pspFileBytes);

            Mockito.when(storageService.getFileAsBytes(anyString(), eq(pspFileName), anyBoolean())).thenReturn(pspFileBytes);

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
            getTokenDTO.setName(THE_BUCKET);
            getTokenDTO.setPsfC(DEFAULT_STRING);
            getTokenDTO.setPsfP(photo == null ? "false" : "true");
            getTokenDTO.setPsp(pspFileName);
            getTokenDTO.setIn("sample.pdf");
            getTokenDTO.setSignTimeout(1000);
            getTokenDTO.setOut(THE_OUT_FILENAME);
            String tokenStr = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_TOKEN_FOR_DOCUMENT, getTokenDTO, String.class);

            // get data to sign
            GetDataToSignForTokenDTO dataToSignDTO = new GetDataToSignForTokenDTO(tokenStr, 0, clientSignatureParameters);
            DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_DATA_TO_SIGN_FOR_TOKEN, dataToSignDTO, DataToSignDTO.class);

            // sign
            SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

            // This code will be triggered when signDocumentForToken will store it's output file to the file store
            doAnswer(invocation -> {
                // So here we're going to check the output PDF file
                byte[] signedBytes = (byte[]) invocation.getArgument(2);

                /*
                File pdf = new File(pspFile.getParent(), pspFileName.substring(0, pspFileName.length() - 4) + ".pdf");
                new InMemoryDocument(signedBytes).save(pdf.getPath());
                 */

                String defaultCoordinates = (new ObjectMapper()).readValue(pspFileString, PdfSignatureProfile.class).defaultCoordinates;
                if (defaultCoordinates == null) defaultCoordinates = DEFAULT_COORDINATES;
                String coords[] = defaultCoordinates.split(",");

                BufferedImage actualFirstPageImage = new PDFRenderer(PDDocument.load(signedBytes)).renderImageWithDPI(0, 72);
                BufferedImage actualSignature = actualFirstPageImage.getSubimage(Integer.parseInt(coords[1]), Integer.parseInt(coords[2]), Integer.parseInt(coords[3]), Integer.parseInt(coords[4]));

                ByteArrayOutputStream outStream = new ByteArrayOutputStream();
                ImageIO.write(actualSignature, "png", outStream);
                PdfVisibleSignatureServiceTest.compareImages(outStream.toByteArray(), pspFileName.substring(0, pspFileName.length() - 4) + (forceV2 ? "_TOV2_TOKEN" : "_TOKEN"));
                return null;
            }).when(storageService).storeFile(eq(THE_BUCKET), eq(THE_OUT_FILENAME), any());

            // sign document
            clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
            SignDocumentForTokenDTO signDocumentDTO = new SignDocumentForTokenDTO(tokenStr, 0, clientSignatureParameters, signatureValue.getValue());
            RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.SIGN_DOCUMENT_FOR_TOKEN, signDocumentDTO, RemoteDocument.class);
    }
}
