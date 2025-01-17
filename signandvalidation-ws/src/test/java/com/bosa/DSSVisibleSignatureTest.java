package com.bosa;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.DSSFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyStore;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSSVisibleSignatureTest {

    @Test
    public void signPAdESBaselineBWithVisibleSignature() throws Exception {

        DSSDocument toSignDocument = new FileDocument(new File("src/test/resources/sample.pdf"));

        try {
            Pkcs12SignatureToken signingToken = new Pkcs12SignatureToken(
                    new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                    new KeyStore.PasswordProtection("123456".toCharArray())
            );

            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            // Preparing parameters for the PAdES signature
            PAdESSignatureParameters parameters = new PAdESSignatureParameters();
            // We choose the level of the signature (-B, -T, -LT, -LTA).
            parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

            // We set the signing certificate
            parameters.setSigningCertificate(privateKey.getCertificate());
            // We set the certificate chain
            parameters.setCertificateChain(privateKey.getCertificateChain());

            // Initialize visual signature and configure
            SignatureImageParameters imageParameters = new SignatureImageParameters();
            // set an image
            imageParameters.setImage(new InMemoryDocument(new FileInputStream("src/test/resources/photo.png")));
            imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);

            // initialize signature field parameters
            SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
            imageParameters.setFieldParameters(fieldParameters);
            // the origin is the left and top corner of the page
            fieldParameters.setOriginX(200);
            fieldParameters.setOriginY(400);
            fieldParameters.setWidth(400);
            fieldParameters.setHeight(200);

            // Initialize text to generate for visual signature
            DSSFont font = new DSSFileFont(new FileInputStream("src/test/resources/fonts/basic.ttf"));
            // Instantiates a SignatureImageTextParameters object
            SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
            // Allows you to set a DSSFont object that defines the text style (see more information in the section "Fonts usage")
            textParameters.setFont(font);
            // Defines the text content
            textParameters.setText("My visual signature \n #1 with a little long text. And then some");
            // Defines the color of the characters
            textParameters.setTextColor(Color.BLUE);
            // Defines the background color for the area filled out by the text
            textParameters.setBackgroundColor(Color.YELLOW);
            // Defines a padding between the text and a border of its bounding area
            textParameters.setPadding(20);
            // TextWrapping parameter allows defining the text wrapping behavior within  the signature field
			/*
			  FONT_BASED - the default text wrapping, the text is computed based on the given font size;
			  FILL_BOX - finds optimal font size to wrap the text to a signature field box;
			  FILL_BOX_AND_LINEBREAK - breaks the words to multiple lines in order to find the biggest possible font size to wrap the text into a signature field box.
			*/
            textParameters.setTextWrapping(TextWrapping.FONT_BASED);
            // Set textParameters to a SignatureImageParameters object
            imageParameters.setTextParameters(textParameters);
            // Specifies a text position relatively to an image (Note: applicable only for joint image+text visible signatures).
            // Thus with _SignerPosition.LEFT_ value, the text will be placed on the left side,
            // and image will be aligned to the right side inside the signature field
            textParameters.setSignerTextPosition(SignerTextPosition.BOTTOM);
            // Specifies a horizontal alignment of a text with respect to its area
            textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.CENTER);
            // Specifies a vertical alignment of a text block with respect to a signature field area
            textParameters.setSignerTextVerticalAlignment(SignerTextVerticalAlignment.TOP);
            parameters.setImageParameters(imageParameters);

            // Create common certificate verifier
            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            // Create PAdESService for signature
            PAdESService service = new PAdESService(commonCertificateVerifier);
            service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
            // Get the SignedInfo segment that need to be signed.
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

            // This function obtains the signature value for signed information using the
            // private key and specified algorithm
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

            // We invoke the xadesService to sign the document with the signature value obtained in
            // the previous step.
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
            signedDocument.save("src/test/resources/out.pdf");

            testFinalDocument(signedDocument, null);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (DSSException e) {
            throw new RuntimeException(e);
        }
    }

    protected DiagnosticData testFinalDocument(DSSDocument signedDocument, List<DSSDocument> detachedContents) {
        assertNotNull(signedDocument);
        assertNotNull(DSSUtils.toByteArray(signedDocument));

        SignedDocumentValidator validator = getValidator(signedDocument);
        if (Utils.isCollectionNotEmpty(detachedContents)) {
            validator.setDetachedContents(detachedContents);
        }
        Reports reports = validator.validateDocument();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        for (SignatureWrapper signatureWrapper : signatures) {
            assertTrue(signatureWrapper.isBLevelTechnicallyValid());

            List<TimestampWrapper> timestampList = signatureWrapper.getTimestampList();
            for (TimestampWrapper timestampWrapper : timestampList) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureValid());
            }
        }

        return diagnosticData;
    }

    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(new CommonCertificateVerifier());
        return validator;
    }

}
