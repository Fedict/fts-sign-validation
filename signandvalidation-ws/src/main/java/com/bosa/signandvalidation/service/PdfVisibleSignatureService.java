package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.PdfSignatureProfile;
import com.bosa.signandvalidation.model.TokenSignInput;
import com.bosa.signingconfigurator.exception.NullParameterException;

import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.ws.dto.RemoteColor;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureImageTextParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureImageParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureFieldParameters;

import lombok.RequiredArgsConstructor;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.common.PDRectangle;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.stereotype.Service;

import java.awt.*;
import java.io.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.text.SimpleDateFormat;

/**
 * The current DSS lib has problems in creating a consistent PDF visible signature,
 * so what we do is call PdfImageBuilder to create an image (containing the text and optionally an input image)
 * that is then given to DSS to be put in the PDf visible signature field.
 */
@Service
@RequiredArgsConstructor
public class PdfVisibleSignatureService {

    public static final String FONTS_PATH_PROPERTY = "fonts.path";
    public static final String DEFAULT_STRING      = "default";
    private static final byte[] DEFAULT_BYTES       = DEFAULT_STRING.getBytes();
    private static final String SURNAME_TOKEN       = "%sn%";
    private static final String GIVENNAME_TOKEN     = "%gn%";
    private static final String NN_TOKEN            = "%nn%";       // Placeholder for National number
    private static final String LEGACY_NN_TOKEN     = "%rrn%";      // Old Placeholder for National number - to delete some day ;-)

    private static final String DEFAULT_TEXT = GIVENNAME_TOKEN + " " + SURNAME_TOKEN;


    // Simple PNG image of a paper and a pen on gray (#D0D0D0) background, size = 125 x 150 pixels
    private static final byte[] IMAGE = Base64.getDecoder().decode(
            "iVBORw0KGgoAAAANSUhEUgAAAH0AAACWCAYAAADzA4dkAAAAAXNSR0IArs4c6QAAAARnQU1BAACx" +
                    "jwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAXkSURBVHhe7Z0tUCMxGIaXMyDBIcGBow5ZXCU4" +
                    "JCjAUcWgAAeqoCgKJCiQdeDAUQcOHBYJips3bJhcr1122/3Lvu8zk2na3t309tkvSb/8dKzb7X4F" +
                    "goo/4aMgQtIJkXRCJJ0QSSdE0gmRdEIknRBJJ0TSCYmVhv36+gpqtVr4TBTJ4+NjMDY2Fj4bjliR" +
                    "fnV1FdZE0aThIlak39zcBPv7+6bearWC9/d3Uxf5MDk5GTSbTVOHh+XlZVMflsTS0dSL/LFNehrS" +
                    "NZAjRNIJkXRCJJ0QSSdE0gmRdEIknRBJJ0TSCZF0QjKVjkkC5IyTlG63G/7t8oLP2O+zJy12EiVv" +
                    "MpU+MTER1uJzdnYW1spLWp9xmOuTBpnOst3d3QWdTif2fw5TtsfHx+GzcrO9vW2mPIfl4+MjaDQa" +
                    "Qb1eD1+JBi0D0NQqEWlK10COEEknRNIJkXRCJJ0QSSdE0gmRdEIknRBJJ0TSCck09z7qpESVSTq5" +
                    "5MWEy9bWVtBut8Nnoh+bm5vB6elp+CwaLyZcNjY2wpoYRFHXKDPpCwsLplVQGVxwjYpAAzlCJJ0Q" +
                    "SSdE0gmRdEIknRBJJyQz6WntAil7mZ2dDf/H/pCZdB92qqTB6+trWPMHTbiMAHaprK6u5pJZQ6sC" +
                    "Sj3hItIlTekayBEi6YRIOiGSToikEyLphEg6IZJOSGbJGeTeLy8vCztMxweSLIP2IiNnP6SIJu4y" +
                    "aC8ycjMzM2FNRFHEMujMpL+8vJhWQSW6FLEMWgM5QiSdEEknRNIJkXRCJJ0QSSdE0gnJTDrShirR" +
                    "pag184r0AilqzXxmEy46ZCiapGvm0TKAUs+yiXRJU7qad0IknRBJJ0TSCZF0QiSdEEknpDLJGZ9+" +
                    "snMYvEjO2A+ZJ0lOVfaNONLPz8/NPgNcB+w52N3dDZ6enoLPz8/wT3xTqead9eTp8fFxk9I9OTkJ" +
                    "jo6OzEQOhINarWYeXTKTjhYh71LUqcpFcn19HczPzwfPz88/y85brZZ5b25uLnh4eDB1Fw3kPMVG" +
                    "98HBgdlYAtl2g4ntCnBD9EPSPQNib29v/4luFAumazGIBr19uUXSPWNtbS1oNpv/RTdAX46CZh0D" +
                    "uEFIuof0i2406Xjc29szI/dBUQ4kveSgCUdTboHsqOheWVkJ3xmMpJcYfCe3fbeVaoUnjW4XSS8h" +
                    "Vqg7ModwiAfDRLeLpJcMKxT09t2IeLw3THS7SHpJ6G2u+43M0dRjPmOY6HaR9BJgo9s213aeA7g3" +
                    "A0BCZpjodpH0AumNbrffBvZmqNfr4SvfS6dHRdILIm5042ZABi5NJD1n4kZ3v5shLSQ9R5JEd+/N" +
                    "kCaSngNliG4XSc+YskS3i6RnRNzothm3rKPbRdIzICq6Ubc3Q2/GLS8qKb2b4g8BQl5cXKG90W1n" +
                    "y/qtdMmbSkpP84cAIfA3XKGDotvOlhUV3S6V3Z+exrr7OAcH4LpANkB0u7IhGTlyPCKqR5GNFgTg" +
                    "39ehBAXxm1D3ZsB7ozblaUrXQG4IcOEHNdd4rSx99yAkPQG/CY26GcqEpMcEAzqfo9tF0mMAqW4i" +
                    "xcfodpH0GNhVKj5HtwuldCRvsLMTX8d+AxEOwS4+RrcLnXQIx05OfIeH+CgQxejLEcWNRuMnS+dj" +
                    "dLvQScd2XmTNDg8P/1mG1Atk2+/EFxcXQafTMa/bjJtv0e1CJx0b93Fqhc2R9wPbe23OHYmp9fX1" +
                    "H9luPt1XKPv0t7c3E6kQOzU19dNn24ma6elp8xxUSbaFUjqwffL9/b0ZlIGlpSWTs8d7eB2lSrIt" +
                    "tNItENput02E47wWe4rD4uKiKVWETjoGZBDsgkEdmnQ0+wzQScdXr52dHSPeFkyhsggHlM07Ihv9" +
                    "uS1MwgF9n86IpBMi6YRIOiGSToikEyLphEg6IZJOiKQTkniHC2ahsAhB5AeWduEQYICpXxwKPAqx" +
                    "pGO5UJV/H8UnsNBjVGI177izfFwAWDXSchAr0kW10ECOEEknRNIJkXRCJJ0QSSdE0gmRdDqC4C+5" +
                    "ObgQrfD45AAAAABJRU5ErkJggg==");

    private final StorageService storageService;

    private final Map<String, byte[]> fontFiles = new ConcurrentHashMap<String, byte[]>(20);
    
    private final Logger logger = Logger.getLogger(PdfVisibleSignatureService.class.getName());

    ///////////////////////////////////////////////////////////////////////////

    public void checkAndFillParams(RemoteSignatureParameters remoteSigParams, RemoteDocument document, TokenSignInput input, String bucket, byte[] photo)
            throws NullParameterException, IOException {

        RemoteSignatureImageParameters sigImgParams = new RemoteSignatureImageParameters();
        remoteSigParams.setImageParameters(sigImgParams);
        RemoteSignatureFieldParameters fieldParams = new RemoteSignatureFieldParameters();
        sigImgParams.setFieldParameters(fieldParams);

        PdfSignatureProfile psp = getPspOrDefaults(bucket, input.getPspFilePath());

        String sigFieldId = input.getPsfN();
        if (sigFieldId != null) {
            fieldParams.setFieldId(sigFieldId);
        } else {
            String inputCoordinates = input.getPsfC();
            if (inputCoordinates == null) return;
            convertFieldCoords(inputCoordinates, psp.defaultCoordinates, fieldParams);
        }

        String text = makeText(psp.texts,
                input.getSignLanguage(),
                remoteSigParams.getBLevelParams().getSigningDate(),
                remoteSigParams.getSigningCertificate());

        byte image[] = photo != null ? photo : psp.image;

        if (psp.version == 1) {
            fillParamsForV1(sigImgParams, document, psp, text, image);
        } else {
            fillParamsForV2(sigImgParams, psp, text, image);
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    private PdfSignatureProfile getPspOrDefaults(String bucket, String pspPath) throws NullParameterException {

        PdfSignatureProfile psp = new PdfSignatureProfile();
        if (pspPath != null) {
            try {
                byte[] json = storageService.getFileAsBytes(bucket, pspPath, false);
                psp = (new ObjectMapper()).readValue(new String(json), PdfSignatureProfile.class);
            }
            catch (Exception e) {
                throw new NullParameterException("Error reading or parsing PDF Signature Profile file: " + e.getMessage());
            }
        }

        if (psp.version == null) psp.version = 1;
        if (psp.bgColor == null) psp.bgColor = "#D0D0D0";   // light gray, same as IMAGE background color;
        if (psp.textSize == null) psp.textSize = 14;
        if (psp.textPadding == null) psp.textPadding = 20;
        if (psp.textAlignH == null) psp.textAlignH = SignerTextHorizontalAlignment.LEFT;
        if (psp.textAlignV == null) psp.textAlignV = SignerTextVerticalAlignment.TOP;
        if (psp.textPos == null) psp.textPos = SignerTextPosition.BOTTOM;
        if (psp.textColor == null) psp.textColor = "#0000FF"; // blue
        if (psp.imageDpi == null) psp.imageDpi = 400;
        if (psp.image != null && Arrays.equals(psp.image, DEFAULT_BYTES)) psp.image = IMAGE;

        if (psp.version == 2) {
            if (psp.textWrapping == null) psp.textWrapping = TextWrapping.FONT_BASED;
            if (psp.imageScaling == null) psp.imageScaling = ImageScaling.ZOOM_AND_CENTER;
            if (psp.horizAlignment == null) psp.horizAlignment = VisualSignatureAlignmentHorizontal.NONE;
            if (psp.vertAlignment == null) psp.vertAlignment = VisualSignatureAlignmentVertical.NONE;
            if (psp.bodyBgColor == null) psp.bodyBgColor = psp.bgColor;
            if (psp.rotation == null) psp.rotation = VisualSignatureRotation.AUTOMATIC;
            if (psp.zoom == null) psp.zoom = 100;

            // DSS rendered fonts are passed in a "Remote" object represented by an in-memory binary file
            // Therefore the "Bold" and "Italic" derived fonts are not supported
            // remove the optional "/bi" from the font name
            psp.font = psp.font == null ? DEFAULT_STRING : psp.font.replaceAll("/[^/]*$", "");
        }

        return psp;
    }

    ///////////////////////////////////////////////////////////////////////////

    static void convertFieldCoords(String inputCoordinates, String pspDefaultCoordinates, RemoteSignatureFieldParameters fieldParams) throws NullParameterException {

        if (DEFAULT_STRING.equals(inputCoordinates)) {
            inputCoordinates = pspDefaultCoordinates;
            if (inputCoordinates == null) {
                throw new NullParameterException("default PDF signature coordinates requested, but these we not specified in the psp (or no psp)");
            }
        }
        String[] coords = inputCoordinates.split(",");
        if (coords.length != 5) {
            throw new NullParameterException("expected 5 values for PDF signature coordinates but was: '" + inputCoordinates + "'");
        }
        fieldParams.setPage(Integer.parseInt(coords[0]));
        fieldParams.setOriginX(Float.parseFloat(coords[1]));
        fieldParams.setOriginY(Float.parseFloat(coords[2]));
        fieldParams.setWidth(Float.parseFloat(coords[3]));
        fieldParams.setHeight(Float.parseFloat(coords[4]));
    }

    ///////////////////////////////////////////////////////////////////////////

    static String makeText(LinkedHashMap<String,String> texts, String lang, Date signingDate, RemoteCertificate signingCert) throws NullParameterException {
        String text = DEFAULT_TEXT;
        if (null != texts && texts.size() != 0) {
            if (null != lang) {
                text = texts.get(lang);
                if (null == text)
                    throw new NullParameterException("language '" + lang + "' not specified in the psp file");
            }
            else
                text = texts.values().iterator().next(); // get the 1st text
        }

        CertInfo certInfo = new CertInfo(signingCert);

        text = text.replace(SURNAME_TOKEN, certInfo.getSurname())
                .replace(GIVENNAME_TOKEN, certInfo.getGivenName())
                .replace(LEGACY_NN_TOKEN, certInfo.getSerialNumber())
                .replace(NN_TOKEN, certInfo.getSerialNumber());

        if (null == lang)
            lang = "en";
        try {
            int idx = text.indexOf("%d(");
            while (-1 != idx) {
                int endIdx = text.indexOf(")%", idx);
                if (-1 == endIdx)
                    break;
                String dateFormat = text.substring(idx + 3, endIdx);
                SimpleDateFormat sdf = new SimpleDateFormat(dateFormat, new Locale(lang));
                String dateStr = sdf.format(signingDate);
                text = text.substring(0, idx) + dateStr + text.substring(endIdx + 2);

                idx = text.indexOf("%d(", idx + 1);
            }
        }
        catch (Exception e) {
            e.printStackTrace();
            throw new NullParameterException("Bad date format for PDF visible signature: " + e.getMessage());
        }

        return text;
    }

    ///////////////////////////////////////////////////////////////////////////

    public void fillParamsForV2(RemoteSignatureImageParameters sigImgParams, PdfSignatureProfile psp, String text, byte[] image) throws IOException {
        RemoteSignatureImageTextParameters textParams = new RemoteSignatureImageTextParameters();
        sigImgParams.setTextParameters(textParams);

        textParams.setSize(psp.textSize);
        textParams.setTextWrapping(psp.textWrapping);
        textParams.setTextColor(makeColor(psp.textColor));
        textParams.setBackgroundColor(makeColor(psp.bgColor));
        textParams.setText(text);
        textParams.setPadding(psp.textPadding.floatValue());
        textParams.setSignerTextPosition(psp.textPos);
        textParams.setSignerTextVerticalAlignment(psp.textAlignV);
        textParams.setSignerTextHorizontalAlignment(psp.textAlignH);
        RemoteDocument rd = new RemoteDocument(readFontFromFileOrCache(psp.font), psp.font);
        textParams.setFont(rd);

        if (image != null) sigImgParams.setImage(new RemoteDocument(image, "image.png"));
        sigImgParams.setDpi(psp.imageDpi);

        sigImgParams.setImageScaling(psp.imageScaling);
        sigImgParams.setBackgroundColor(makeColor(psp.bodyBgColor));
        sigImgParams.setZoom(psp.zoom);

        // Alignment of the signature relative to page borders
        sigImgParams.setAlignmentHorizontal(psp.horizAlignment);
        sigImgParams.setAlignmentVertical(psp.vertAlignment);

        // Adapt signature rotation
        sigImgParams.setRotation(psp.rotation);
    }

    ///////////////////////////////////////////////////////////////////////////

    private RemoteColor makeColor(String color) {
        if (color.length() != 7) throw new IllegalArgumentException("Invalid color code specified: " + color);

        return new RemoteColor(Integer.parseInt(color.substring(1, 3), 16),
                Integer.parseInt(color.substring(3, 5), 16),
                Integer.parseInt(color.substring(5, 7), 16));
    }

    ///////////////////////////////////////////////////////////////////////////

    private void fillParamsForV1(RemoteSignatureImageParameters sigImgParams, RemoteDocument document, PdfSignatureProfile psp, String text, byte[] image) throws NullParameterException {

        RemoteSignatureFieldParameters fieldParams = sigImgParams.getFieldParameters();
        float xPdfField = 0; // width of the PDF visible signature field
        float yPdfField = 0; // height of the PDF visible signature field
        if (fieldParams.getFieldId() != null) {
            // Pdf field -> get w/h from PDF
            PDRectangle rect = getPdfSignatureRectangle(document, fieldParams.getFieldId());
            xPdfField = rect.getWidth();
            yPdfField = rect.getHeight();
        } else {
            xPdfField = fieldParams.getWidth();
            yPdfField = fieldParams.getHeight();
        }

        try {
            RemoteDocument imageDoc = new RemoteDocument();
            sigImgParams.setImage(imageDoc);

            imageDoc.setBytes(PdfImageBuilder.makePdfImage(
                    (int)xPdfField, (int)yPdfField,
                    psp.bgColor,
                    psp.textPadding,
                    text,
                    psp.textColor,
                    getTextPos(psp.textPos),
                    getHorizontalAlign(psp.textAlignH),
                    getVerticalAlign(psp.textAlignV),
                    getFont(psp.font, psp.textSize),
                    image));
        }
        catch (Exception e) {
            logger.log(Level.SEVERE, e.toString());
            throw new NullParameterException(e.getMessage());
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    int getTextPos(SignerTextPosition textPos) {
        switch(textPos) {
            case TOP:    return PdfImageBuilder.POS_TOP;
            case BOTTOM: return PdfImageBuilder.POS_BOTTOM;
            case LEFT:   return PdfImageBuilder.POS_LEFT;
        }
        return PdfImageBuilder.POS_RIGHT;
    }

    ///////////////////////////////////////////////////////////////////////////

    int getHorizontalAlign(SignerTextHorizontalAlignment textAlignH) {
        switch(textAlignH) {
            case LEFT:  return PdfImageBuilder.HALIGN_LEFT;
            case RIGHT: return PdfImageBuilder.HALIGN_RIGHT;
        }
        return PdfImageBuilder.HALIGN_CENTER;
    }

    ///////////////////////////////////////////////////////////////////////////

    int getVerticalAlign(SignerTextVerticalAlignment textAlignV) {
        switch(textAlignV) {
            case TOP:  return PdfImageBuilder.VALIGN_TOP;
            case BOTTOM: return PdfImageBuilder.VALIGN_BOTTOM;
        }
        return PdfImageBuilder.VALIGN_MIDDLE;
    }

    ///////////////////////////////////////////////////////////////////////////

    public static class PdfVisibleSignatureException extends RuntimeException {

        public PdfVisibleSignatureException(String mesg) {
            super(mesg);
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    // Check if the sigFieldId is present, and get its enclosing rectangle
    private static PDRectangle getPdfSignatureRectangle(RemoteDocument document, String sigFieldId) {
        List<String> fieldIds = new ArrayList<>();

        try {
            PDDocument pdfDoc = PDDocument.load(new ByteArrayInputStream(document.getBytes()), (String) null);

            List<PDSignatureField> sigFields = pdfDoc.getSignatureFields();
            if (sigFields.size() == 0)
                throw new PdfVisibleSignatureException("A PDF signature field was specified but the PDF does not contain one");

            for (PDSignatureField sigField : sigFields) {
                String name = sigField.getPartialName();
                fieldIds.add(name);
                if (sigFieldId.equals(name)) {
                    if (null != sigField.getSignature()) {
                        throw new PdfVisibleSignatureException("The specified PDF signature field already contains a signature");
                    }
                    PDAnnotationWidget widget = sigField.getWidget();
                    return widget.getRectangle();
                }
            }
            throw new PdfVisibleSignatureException("Bad PDF signature field specified, available field(s) are: " + fieldIds.toString());

        } catch (IOException e) {
            throw new PdfVisibleSignatureException(e.toString());
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    Font getFont(String fontStr, int fontSize) {
        // Split the fontStr into fontName and fontType
        Object[] info = PdfImageBuilder.getFontNameAndStyle(fontStr);
        String fontName = (String) info[0];
        int fontType = ((Integer) info[1]).intValue();

        byte[] buf = readFontFromFileOrCache(fontName);
        if (null != buf) {
            // Font comes from disk
            try {
                Font baseFont = Font.createFont(Font.TRUETYPE_FONT, new ByteArrayInputStream(buf));
                return baseFont.deriveFont(fontType, fontSize);
            }
            catch(Exception e) {
                logger.log(Level.WARNING, "Font.createFont(" + fontStr + ") failed: " + e.toString());
                return new Font(null, fontType, fontSize);
            }
        }
        else {
            // Assume it's a system font
            if (fontName.equals(DEFAULT_STRING))
                fontName = null;
            return new Font(fontName, fontType, fontSize);
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    byte[] readFontFromFileOrCache(String fontName) {
        if (fontFiles.containsKey(fontName))
            return fontFiles.get(fontName);
        byte[] buf = readFontFromFile(fontName);
        if (buf != null) fontFiles.put(fontName, buf);
        return buf;
    }

    ///////////////////////////////////////////////////////////////////////////

    byte[] readFontFromFile(String fontName) {
        try {
            String fontsPath = System.getProperty(FONTS_PATH_PROPERTY);
            if (null == fontsPath) {
                logger.log(Level.WARNING, "System property not set: " + FONTS_PATH_PROPERTY);
                return null;
            }
            File fontsDir = new File(fontsPath);
            if (!fontsDir.exists()) {
                logger.log(Level.WARNING, "Fonts dir does not exist: " + fontsDir.getAbsolutePath());
                return null;
            }
            File fontsFile = new File(fontsDir, fontName + ".ttf");
            if (!fontsFile.exists()) {
                logger.log(Level.INFO, "Font " + fontName + ".ttf not found on disk");
                return null;
            }
            byte[] buf = new byte[(int) fontsFile.length()];
            FileInputStream fis = new FileInputStream(fontsFile);
            fis.read(buf);
            fis.close();
            logger.log(Level.INFO, "Font " + fontName + ".ttf read from disk and cached");
            return buf;
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}

