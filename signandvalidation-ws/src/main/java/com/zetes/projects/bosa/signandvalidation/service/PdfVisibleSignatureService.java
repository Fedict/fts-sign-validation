package com.zetes.projects.bosa.signandvalidation.service;

import com.zetes.projects.bosa.signandvalidation.TokenParser;
import com.zetes.projects.bosa.signandvalidation.model.PdfSignatureProfile;
import com.zetes.projects.bosa.signingconfigurator.exception.NullParameterException;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteColor;
import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteBLevelParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureImageParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureFieldParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.model.InMemoryDocument;

import com.fasterxml.jackson.databind.ObjectMapper;;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

import java.util.logging.Logger;
import java.util.logging.Level;
import java.io.File;
import java.io.FileInputStream;
import java.util.List;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Date;
import java.text.SimpleDateFormat;

@Service
public class PdfVisibleSignatureService {

    private static final String FONTS_PATH_PROPERTY = "fonts.path";

    @Autowired
    private PAdESService padesService;

    @Autowired
    private ObjectStorageService ObjStorageService;

    private File fontsDir;
    private HashMap<String, RemoteDocument> fonts = new HashMap<String, RemoteDocument>(20);
    
    public PdfVisibleSignatureService() {
    }

    private Logger logger = Logger.getLogger(PdfVisibleSignatureService.class.getName());

    public void checkAndFillParams(RemoteSignatureParameters remoteSigParams, RemoteDocument document, TokenParser tokenParser, byte[] photo)
            throws NullParameterException, ObjectStorageService.InvalidTokenException {
        String sigFieldId = tokenParser.getPsfN();
        String sigFieldCoords = tokenParser.getPsfC();
        if (null == sigFieldId && null == sigFieldCoords)
            return;

        // Checks
        if (null != sigFieldId) {
            List<String> list = padesService.getAvailableSignatureFields(new InMemoryDocument(document.getBytes()));
            if (list.size() == 0)
                throw new PdfVisibleSignatureException("A PDF signature field was specified but the PDF does not contain one");
            else if (!list.contains(sigFieldId))
                throw new PdfVisibleSignatureException("Bad PDF signature field specified, available field(s) are: " + list.toString());
        }

        fillParams(remoteSigParams, tokenParser, photo);
    }

    public void fillParams(RemoteSignatureParameters remoteSigParams, TokenParser tokenParser, byte[] photo)
            throws NullParameterException, ObjectStorageService.InvalidTokenException {
        String sigFieldId = tokenParser.getPsfN();
        String sigFieldCoords = tokenParser.getPsfC();
        String lang = tokenParser.getLang();

        if (null == sigFieldId && null == sigFieldCoords)
            return;

        Date signingDate = remoteSigParams.getBLevelParams().getSigningDate();

        // Defaults
        LinkedHashMap<String,String> texts = null;
        String font = null;
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
        if (null != tokenParser && null != tokenParser.getPsp()) {
            byte[] json = ObjStorageService.getFileForToken(tokenParser.getPsp(), tokenParser.getCid());
            try {
                PdfSignatureProfile psp = (new ObjectMapper()).readValue(new String(json), PdfSignatureProfile.class);

                if (null != psp.bgColor)       bgColor = psp.bgColor;
                if (null != psp.texts)         texts = psp.texts;
                if (null != psp.font)          font = psp.font;
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
        if (null != sigFieldId)
            sigFieldParams.setFieldId(sigFieldId);
        else {
            if (!"default".equals(sigFieldCoords))
                psfC = sigFieldCoords;
            if (null == psfC)
                throw new NullParameterException("default PDF signature coordinates requested, but these we not specified in the psp (or no psp)");
            fillCoordinates(sigFieldParams, psfC);
        }

        fillParams(remoteSigParams, texts, lang, signingDate, font, textPadding, textSize, textAlignH, textAlignV, textPos, textColor, bgColor, imageDpi, image);
    }

    void fillParams(RemoteSignatureParameters remoteSigParams, LinkedHashMap<String,String> texts, String lang, Date signingDate, String font, int textPadding, int textSize,
        SignerTextHorizontalAlignment textAlignH, SignerTextVerticalAlignment textAlignV, SignerTextPosition textPos,
        String textColor, String bgColor, int imageDpi, byte[] image) throws NullParameterException {
            RemoteSignatureImageParameters sigImgParams = remoteSigParams.getImageParameters();

            if (null != image) {
                RemoteDocument imageDoc = new RemoteDocument();
                imageDoc.setBytes(image);
                sigImgParams.setImage(imageDoc);
                sigImgParams.setDpi(imageDpi);
                sigImgParams.setBackgroundColor(makeColor(bgColor));
            }

            RemoteSignatureImageTextParameters sigImgTextParams = new RemoteSignatureImageTextParameters();
            sigImgParams.setTextParameters(sigImgTextParams);
            sigImgTextParams.setText(makeText(texts, lang, signingDate, remoteSigParams.getSigningCertificate()));
            sigImgTextParams.setTextColor(makeColor(textColor));
            sigImgTextParams.setSignerTextHorizontalAlignment(textAlignH);
            sigImgTextParams.setSignerTextVerticalAlignment(textAlignV);
            sigImgTextParams.setSignerTextPosition(textPos);
            sigImgTextParams.setSize(textSize);
            sigImgTextParams.setPadding((float) textPadding);
            sigImgTextParams.setBackgroundColor(makeColor(bgColor));
            RemoteDocument fontDoc = readFont(font);
            if (null != fontDoc)
                sigImgTextParams.setFont(fontDoc);
    }

    RemoteDocument readFont(String font) {
        if (null == font)
            return null;
        RemoteDocument fontDoc = fonts.get(font);
        if (null == fontDoc) {
            byte[] fontBytes = readFontFromFile(font);
            if (null != fontBytes) {
                fontDoc = new RemoteDocument();
                fontDoc.setBytes(fontBytes);
                fonts.put(font, fontDoc);
                logger.log(Level.INFO, "Loaded font: " + font);
            }
        }
        return fontDoc;
    }

    byte[] readFontFromFile(String font) {
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
            File fontsFile = new File(fontsDir, font + ".ttf");
            if (!fontsFile.exists()) {
                logger.log(Level.WARNING, "Font file does not exist: " + fontsFile.getAbsolutePath());
                return null;
            }
            byte[] buf = new byte[(int) fontsFile.length()];
            FileInputStream fis = new FileInputStream(fontsFile);
            fis.read(buf);
            fis.close();
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

        if (text.contains("%sn%"))
            text = text.replace("%sn%", certInfo.getSurname());
        if (text.contains("%gn%"))
            text = text.replace("%gn%", certInfo.getGivenName());
        if (text.contains("%rrn%"))
            text = text.replace("%rrn%", certInfo.getRRN());

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
    static void fillCoordinates(RemoteSignatureFieldParameters sigFieldParams, String pdfSigCoords) throws NullParameterException {
        String[] coords = pdfSigCoords.split(",");
        if (coords.length != 5)
            throw new NullParameterException("expected 5 values for PDF signature coordinates but was: '" + pdfSigCoords + "'");
        sigFieldParams.setPage(Integer.parseInt(coords[0]));
        sigFieldParams.setOriginX((float) Integer.parseInt(coords[1]));
        sigFieldParams.setOriginY((float) Integer.parseInt(coords[2]));
        sigFieldParams.setWidth((float) Integer.parseInt(coords[3]));
        sigFieldParams.setHeight((float) Integer.parseInt(coords[4]));
    }

    // #RRGGBB or #RRGGBB color code where
    // E.g. #0000FF for blue
    static RemoteColor makeColor(String cc) throws NullParameterException {
        if (cc.length() != 7)
            throw new NullParameterException("Invalid color code specified: " + cc);
        int r = Integer.parseInt(cc.substring(1, 3), 16);
        int g = Integer.parseInt(cc.substring(3, 5), 16);
        int b = Integer.parseInt(cc.substring(5, 7), 16);
	return new RemoteColor(r, g, b);
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
    private static final SignerTextHorizontalAlignment TEXT_HOR_ALIGN = SignerTextHorizontalAlignment.CENTER;
    private static final SignerTextVerticalAlignment TEXT_VER_ALIGN = SignerTextVerticalAlignment.MIDDLE;
    private static final SignerTextPosition TEXT_POS = SignerTextPosition.BOTTOM;
    private static final String TEXT = "%gn% %sn%";
    private static final String TEXT_COLOR = "#0000FF"; // blue
    private static final String BG_COLOR = "#D0D0D0";   // light gray, same as IMAGE background color
    private static final int IMAGE_DPI = 400;
    private static final byte[] DEFAULT = "default".getBytes();
    private static final byte[] IMAGE = Base64.getDecoder().decode(
        "iVBORw0KGgoAAAANSUhEUgAAAlgAAACWCAYAAAACG/YxAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAhSSURBVHhe7d0xUBNbG4Dh5W9Mye0sodMOOkvsKLGjxArsoHKsxE6rhAqooMTKlHTaSWc67aCzTRkrfr+d3UxECCEcQ7L7PDM7nE28d7xhrvP67bJnrtPpXGYAACTzv+IrAACJCCwAgMQEFgBAYgILACAxgQUAkJjAAgBITGABACQmsAAAEhNYAACJCSwAgMRslQMVdXl5mS0vLxdnPKRv375lc3NzxRlQByZYUFEfP34sVjw03wuoHxMsqKh2u53t7u7m62azmXW73XzNZMzPz2c7Ozv5Or4Pa2tr+RqoB4EFFTUYWHG5kMkrLwsKLKgflwgBABITWAAAiQksAIDEBBYAQGICCwAgMYEFAJCYwAIASExgAQAkJrAAABITWAAAiQksAIDEBBbwh9igOPbQu8vR6XSKf3p6xe/xut/7XY9yA2eAYQQW8IdGo1GsRnd4eFispleq3+M4nw9QP3O//1Znm32ooHa7ne3u7ubry8vR/zf/8uVLdnp6OnJIdLvdrNVqFWfTbXt7O5ufny/O7q7X62Wrq6vZyspK8cpwMfEK8X1YW1vL10A9CCyoqHEDi3QEFtSXS4QAAIkJLACAxAQWAEBiAgsAIDGBBQCQmMACAEhMYAEAJCawAAASE1gAAIkJLACAxAQWAEBi9iKEihp3L8L7bohcZXfd2NpehFBfAgsqapzAevXqVXZwcFCccZ2tra1sf3+/OBtOYEF9uUQI9G1ubhYrbuIzAkYhsIC+paWlfNrluPmIzwjgNgILACAxgQUAkJjAAgBITGABACQmsAAAEhNYAACJCSwAgMQEFtDX6XTyp49X/VhcXCz+iwH+DYEF9B0eHhararu4uChWAP+GvQihomz2fL1er5etr69P5InsMS0L9iKE+hFYUFHjBhbpCCyoL5cIAQASE1gAAIkJLACAxAQWAEBiAgsAIDGBBQCQmMACAEhMYAEAJOZBo1BR4zxoNPYiPDk5yRqNRvEKV3W73azVahVnw3nQKNSXwIKKGiewyiBguK2trWx/f784u5nAgvpyiRDoW1hYKFYMs7m5WawAriewgL7z8/N82uUYfkxio2hgtgksAIDEBBYAQGICCwAgMYEFAJCYwAIASExgAQAkJrAAABITWAAAiQksoC+2dnEMPxYXF4tPC+BmAgvgDi4uLooVwM1s9gwVNc5mz9vb29n8/HxxxlW9Xi9bX18feaucmHgFmz1D/QgsqKhxAou0BBbUl0uEAACJCSwAgMQEFgBAYgILACAxgQUAkJjAAgBITGABACTmOVhQUbPwoNFut5u1Wq3irHo8BwvqS2BBRY0TWGUQTNLW1la2v79fnFXLKIF1dHSUNRqN/HM4OTnJ3rx5k33//j379etX8SuAWeQSIfCgNjc3i1W9PHr0KN92Z29vL/vw4UO+iXTEVVheXs6/ArNLYAF9Mema9DHqvn5V8unTp+zp06fZjx8/svPz8/xzaDab+XtPnjzJzs7O8jUwuwQWwISUU6t3795lCwsLeVjF11BeToz4AmafwAL4xyKiPn/+/MfUKo7SxcVF/gMGwb1XUA0CC+Af29jYyHZ2dv6aWoW49yqOuDQYN7cD1SCwACbguqlVXBaMr2/fvs1/gtD0CqpDYAEkFpcB43JgKcJq2NTqxYsXxTtAVQgsgITimVflvVZlQJVxZWoF9SGwABIo42nwJwQjriKygqkV1IvAArinMp7C1XutYpIV75laQb0ILIAxXb3kd91PCMblwtjf0dQK6kVgAYyhnFqVl/zKfR/DYHiFeLioqRXUi8ACuIOrU6vB+6xCGV4rKyvFK1nW6/WKFVAXAgtgRKNOrSK84sntQH0JLIBbjDq1ui68gHoSWABD3GVqdTW8gPoSWADXMLUC7kNgAVxhagXcl8ACKIw6tSqf1G5qBdxEYAH8NmxqFesyvK4+qR3gOgILmAqdTiePmBRHhNKoBuPp6tQqtrmJJ7EP7i84+KR2gJsILGAqHB4eFqv7i1i6zWA83TS1ivfj15laAXc19/tvjZfFGqiQdrvdD4aYvMyC7e3tfN+++4inpsfWNEtLS8Urf4vPJcIqxNRqMKwiqGLPwPga06r7hFVMxkL8+9fW1vI1UA8CCypqFgPrX7stngbDK9677+VAgQX15RIhUAsROTdd8ovX3GsFpCSwgEq7LZ6GhRfAuAQWUFlxs7upFfAQBBZQSRFQgw8FNbUCJklgAZUUN7MHUyvgIQgsYCbEg0i3trbyRzDcJiZXEVODTK2ASRJYwNSLuFpeXs6fkRWRNUxMp+Leq5hOra6u9p/ubmoFTJLAAqbe3t5e/rT19+/fZysrK8Wrf4uwKp85dXx8nJ2enuavl09qN7UCJkVgAVPv6Ogo63a7/T0Dr3N2dtbfgzAesvry5ct+WA3uLwgwCQILmAk/f/7MJ1ARUf/991//Hqtyk+jHjx/n50FYAQ9NYAEzo7yH6uvXr/kN6+H58+f5HobxXrweh7ACHprAAmZOxNPBwUE+uWo0Glmz2cxff/bsWX4APDSBBUy9uFk9YmpQ3PAelwXj0iHAtBFYwNSLxy28fv06j6zy6PV64gqYWgILmAkxsYr7r8pDXAHTTGABACQmsAAAEhNYAACJCSwAgMQEFgBAYgILACAxgQUAkJjAAgBITGABACQmsAAAEpvrdDqXxRqokHa7ne3u7ubrZrOZdbvdfM1kzM/PZzs7O/l6e3s729jYyNdAPQgsqKjj4+Os1WoVZzyk33/OFiugLlwihIqKicnCwkJxxkPxPYB6MsECAEjMBAsAIDGBBQCQmMACAEhMYAEAJCawAAASE1gAAIkJLACAxAQWAEBSWfZ/SCi4EIxDC1QAAAAASUVORK5CYII=");
}
