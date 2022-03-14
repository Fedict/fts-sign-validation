package com.zetes.projects.bosa.signandvalidation.service;

import com.zetes.projects.bosa.signandvalidation.model.PdfSignatureProfile;
import com.zetes.projects.bosa.signandvalidation.model.TokenSignInput;
import com.zetes.projects.bosa.signingconfigurator.exception.NullParameterException;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureImageParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureFieldParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.common.PDRectangle;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.logging.Logger;
import java.util.logging.Level;
import java.io.File;
import java.io.FileInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.awt.Font;

/**
 * The current DSS lib has problems in creating a consistent PDF visible signature,
 * so what we do is call PdfImageBuilder to create an image (containing the text and optionally an input image)
 * that is then given to DSS to be put in the PDf visible signature field.
 */
@Service
public class PdfVisibleSignatureService {

    private static final String FONTS_PATH_PROPERTY = "fonts.path";

    @Autowired
    private PAdESService padesService;

    @Autowired
    private StorageService storageService;

    private File fontsDir;
    private HashMap<String, byte[]> fontFiles = new HashMap<String, byte[]>(20);
    
    public PdfVisibleSignatureService() {
    }

    private Logger logger = Logger.getLogger(PdfVisibleSignatureService.class.getName());

    public void checkAndFillParams(RemoteSignatureParameters remoteSigParams, RemoteDocument document, TokenSignInput input, String bucket, byte[] photo)
            throws NullParameterException {

        String sigFieldId = input.getPsfN();
        String sigFieldCoords = input.getPsfC();
        if (null == sigFieldId && null == sigFieldCoords)
            return;

        int xPdfField = 0; // width of the PDF visible signature field
        int yPdfField = 0; // height of the PDF visible signature field

        // Check if the sigFieldId is present, and get its width (xPdfField) and height (yPdfField)
        if (null != sigFieldId) {
            List<String> fieldIds = new ArrayList<>();

            try {
                PDDocument pdfDoc = PDDocument.load(new ByteArrayInputStream(document.getBytes()), (String) null);

                List<PDSignatureField> sigFields = pdfDoc.getSignatureFields();
                if (sigFields.size() == 0)
                    throw new PdfVisibleSignatureException("A PDF signature field was specified but the PDF does not contain one");

                boolean sigFieldFound = false;
                for (PDSignatureField sigField : sigFields) {
                    String name = sigField.getPartialName();
                    fieldIds.add(name);
                    if (!sigFieldId.equals(name))
                        continue;
                    if (null != sigField.getSignature())
                        throw new PdfVisibleSignatureException("The specified PDF signature field already contains a signature");
                    sigFieldFound = true;
                    PDAnnotationWidget widget = sigField.getWidget();
                    PDRectangle rect = widget.getRectangle();
                    xPdfField = (int) rect.getWidth();
                    yPdfField = (int) rect.getHeight();
                    break;
                }

                if (!sigFieldFound)
                    throw new PdfVisibleSignatureException("Bad PDF signature field specified, available field(s) are: " + fieldIds.toString());
            } catch (IOException e) {
                throw new PdfVisibleSignatureException(e.toString());
            }
        }

        fillParams(remoteSigParams, input, bucket, photo, xPdfField, yPdfField);
    }

    private void fillParams(RemoteSignatureParameters remoteSigParams, TokenSignInput input, String bucket, byte[] photo, int xPdfField, int yPdfField)
            throws NullParameterException {
        String sigFieldId = input.getPsfN();
        String sigFieldCoords = input.getPsfC();
        String lang = input.getSignLanguage();

        if (null == sigFieldId && null == sigFieldCoords)
            return;

        Date signingDate = remoteSigParams.getBLevelParams().getSigningDate();

        // Defaults
        LinkedHashMap<String,String> texts = null;
        String fontStr = null;
        int textPadding = TEXT_PADDING;
        int textSize = TEXT_SIZE;
        SignerTextHorizontalAlignment textAlignH = TEXT_HOR_ALIGN;
        SignerTextVerticalAlignment textAlignV = TEXT_VER_ALIGN;
        SignerTextPosition textPos = TEXT_POS;
        String textColor = TEXT_COLOR;
        String bgColor = BG_COLOR;
        int imageDpi = IMAGE_DPI;
        byte[] image = null;
        String psfC = null;

        // If present, get the profile JSON from the minio, parse it and overwrite the defaults for all values present
        if (null != input && null != input.getPspFileName()) {
            try {
                byte[] json = storageService.getFileAsBytes(bucket, input.getPspFileName(), false);
                PdfSignatureProfile psp = (new ObjectMapper()).readValue(new String(json), PdfSignatureProfile.class);

                if (null != psp.bgColor)       bgColor = psp.bgColor;
                if (null != psp.texts)         texts = psp.texts;
                if (null != psp.font)          fontStr = psp.font;
                if (null != psp.textSize)      textSize = psp.textSize;
                if (null != psp.textPadding)   textPadding = psp.textPadding;
                if (null != psp.textAlignH)    textAlignH = SignerTextHorizontalAlignment.valueOf(psp.textAlignH);
                if (null != psp.textAlignV)    textAlignV = SignerTextVerticalAlignment.valueOf(psp.textAlignV);
                if (null != psp.textPos)       textPos = SignerTextPosition.valueOf(psp.textPos);
                if (null != psp.textColor)     textColor = psp.textColor;
                if (null != psp.imageDpi)      imageDpi = psp.imageDpi;
                if (null != psp.image)         image = psp.image;
                if (null != psp.defaultCoordinates)    psfC = psp.defaultCoordinates;
            }
            catch (Exception e) {
                throw new NullParameterException("Error parsing PDF Signature Profile file: " + e.getMessage());
            }
        }
        if (null != photo)
		image = photo;
	else if (Arrays.equals(image, DEFAULT))
		image = IMAGE;

        RemoteSignatureImageParameters sigImgParams = new RemoteSignatureImageParameters();
        remoteSigParams.setImageParameters(sigImgParams);

        RemoteSignatureFieldParameters sigFieldParams = new RemoteSignatureFieldParameters();
        sigImgParams.setFieldParameters(sigFieldParams);
        if (null != sigFieldId) {
            sigFieldParams.setFieldId(sigFieldId);
	}
        else {
            if (!"default".equals(sigFieldCoords))
                psfC = sigFieldCoords;
            if (null == psfC)
                throw new NullParameterException("default PDF signature coordinates requested, but these we not specified in the psp (or no psp)");
            int[] ret = fillCoordinates(sigFieldParams, psfC);
            xPdfField = ret[0];
            yPdfField = ret[1];
        }

        fillParams(remoteSigParams, texts, lang, signingDate, fontStr, textPadding, textSize, textAlignH, textAlignV, textPos, textColor, bgColor, imageDpi, image, xPdfField, yPdfField);
    }

    void fillParams(RemoteSignatureParameters remoteSigParams, LinkedHashMap<String,String> texts, String lang, Date signingDate, String fontStr, int textPadding, int textSize,
        SignerTextHorizontalAlignment textAlignH, SignerTextVerticalAlignment textAlignV, SignerTextPosition textPos,
        String textColor, String bgColor, int imageDpi, byte[] image, int xPdfField, int yPdfField) throws NullParameterException {
            RemoteSignatureImageParameters sigImgParams = remoteSigParams.getImageParameters();

            String text = makeText(texts, lang, signingDate, remoteSigParams.getSigningCertificate());
            int txtPos = getTextPos(textPos);
            int txtAlignH = getHorizontalAlign(textAlignH);
            int txtAlignV = getVerticalAlign(textAlignV);
            Font font = getFont(fontStr, textSize);

            try {
                byte[] pdfVisbleSigImage = PdfImageBuilder.makePdfImage(
                    xPdfField, yPdfField,
                    bgColor, textPadding,
                    text, textColor, txtPos, txtAlignH, txtAlignV, font,
                    image);

                RemoteDocument imageDoc = new RemoteDocument();
                imageDoc.setBytes(pdfVisbleSigImage);
                sigImgParams.setImage(imageDoc);
                sigImgParams.setDpi(imageDpi);
            }
            catch (Exception e) {
                logger.log(Level.SEVERE, e.toString());
                throw new NullParameterException(e.getMessage());
            }
    }

    int getTextPos(SignerTextPosition textPos) {
        switch(textPos) {
            case TOP:    return PdfImageBuilder.POS_TOP;
            case BOTTOM: return PdfImageBuilder.POS_BOTTOM;
            case LEFT:   return PdfImageBuilder.POS_LEFT;
            default:     return PdfImageBuilder.POS_RIGHT;
        }
    }

    int getHorizontalAlign(SignerTextHorizontalAlignment textAlignH) {
        switch(textAlignH) {
            case LEFT:  return PdfImageBuilder.HALIGN_LEFT;
            case RIGHT: return PdfImageBuilder.HALIGN_RIGHT;
            default:    return PdfImageBuilder.HALIGN_CENTER;
        }
    }

    int getVerticalAlign(SignerTextVerticalAlignment textAlignV) {
        switch(textAlignV) {
            case TOP:  return PdfImageBuilder.VALIGN_TOP;
            case BOTTOM: return PdfImageBuilder.VALIGN_BOTTOM;
            default:    return PdfImageBuilder.VALIGN_MIDDLE;
        }
    }

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
            if (fontName.equals("default"))
                fontName = null;
            return new Font(fontName, fontType, fontSize);
        }
    }

    byte[] readFontFromFileOrCache(String fontName) {
        if (fontFiles.containsKey(fontName))
            return fontFiles.get(fontName);
        byte[] buf = readFontFromFile(fontName);
        fontFiles.put(fontName, buf);
        return buf;
    }

    byte[] readFontFromFile(String fontName) {
        try {
            String fontsPath = System.getProperty(FONTS_PATH_PROPERTY);
            if (null == fontsPath) {
                logger.log(Level.WARNING, "System property not set: " + FONTS_PATH_PROPERTY);
                return null;
            }
            fontsDir = new File(fontsPath);
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

    static String makeText(LinkedHashMap<String,String> texts, String lang, Date signingDate, RemoteCertificate signingCert) throws NullParameterException {
        String text = TEXT;
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

        text = text.replace("%sn%", certInfo.getSurname()).
                replace("%gn%", certInfo.getGivenName())
                .replace("%rrn%", certInfo.getSerialNumber())
                .replace("%nn%", certInfo.getSerialNumber());

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

    // Example of pdfSigCoords: "1,200,50,300,50"   meaning: page,x,y,width,height
    static int[] fillCoordinates(RemoteSignatureFieldParameters sigFieldParams, String pdfSigCoords) throws NullParameterException {
        String[] coords = pdfSigCoords.split(",");
        if (coords.length != 5)
            throw new NullParameterException("expected 5 values for PDF signature coordinates but was: '" + pdfSigCoords + "'");
        sigFieldParams.setPage(Integer.parseInt(coords[0]));
        sigFieldParams.setOriginX((float) Integer.parseInt(coords[1]));
        sigFieldParams.setOriginY((float) Integer.parseInt(coords[2]));
	int width = Integer.parseInt(coords[3]);
        sigFieldParams.setWidth((float) width);
	int heigth = Integer.parseInt(coords[4]);
        sigFieldParams.setHeight((float) heigth);
        return new int[] {width, heigth};
    }

    ///////////////////////////////////////////////////////////////////////////

    public static class PdfVisibleSignatureException extends RuntimeException {

        public PdfVisibleSignatureException(String mesg) {
            super(mesg);
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    // Default values
    private static final int TEXT_SIZE = 14;
    private static final int TEXT_PADDING = 20;
    private static final SignerTextHorizontalAlignment TEXT_HOR_ALIGN = SignerTextHorizontalAlignment.LEFT;
    private static final SignerTextVerticalAlignment TEXT_VER_ALIGN = SignerTextVerticalAlignment.TOP;
    private static final SignerTextPosition TEXT_POS = SignerTextPosition.BOTTOM;
    private static final String TEXT = "%gn% %sn%";
    private static final String TEXT_COLOR = "#0000FF"; // blue
    private static final String BG_COLOR = "#D0D0D0";   // light gray, same as IMAGE background color
    private static final int IMAGE_DPI = 400;
    private static final byte[] DEFAULT = "default".getBytes();
    // Simple PNG image of a paper and a pen on gray (#D0D0D0) background, size = 125 x 150 pixels
    private static final byte[] IMAGE = Base64.getDecoder().decode(
        "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" +
        "ObgQrfD45AAAAABJRU5ErkJggg==");
}
