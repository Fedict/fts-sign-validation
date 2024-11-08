package com.bosa.signandvalidation.exceptions;

import com.bosa.signandvalidation.controller.SigningController;
import com.bosa.signandvalidation.model.TrustSources;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.InvalidParameterException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Utils {

    public static final DateTimeFormatter logDateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyyMMddHHmmssSSS").withZone(ZoneId.systemDefault());

    // TODO : check if SigningController.class is the right logger name to use for all controllers
    public static final Logger logger = Logger.getLogger(SigningController.class.getName());

    public static void logAndThrowEx(HttpStatus httpStatus, String errConst, Exception e) {
        logAndThrowEx(null, httpStatus, errConst, null, e);
    }

    public static void logAndThrowEx(HttpStatus httpStatus, String errConst, String details) {
        logAndThrowEx(null, httpStatus, errConst, details, null);
    }

    public static void logAndThrowEx(HttpStatus httpStatus, String errConst, String details, Exception e) {
        logAndThrowEx(null, httpStatus, errConst, details, e);
    }

    public static void logAndThrowEx(String token, HttpStatus httpStatus, String errConst, Exception e) {
        logAndThrowEx(token, httpStatus, errConst, null, e);
    }

    public static void logAndThrowEx(String token, HttpStatus httpStatus, String errConst, String details) {
        logAndThrowEx(token, httpStatus, errConst, details, null);
    }

    public static void logAndThrowEx(String token, HttpStatus httpStatus, String errConst, String details, Exception e) {
        if (e instanceof ResponseStatusException)
            throw (ResponseStatusException) e; // we already logged this exception

        // To be returned in the response
        String ref = logDateTimeFormatter.format(Instant.now());
        String mesg = ref + "||" + errConst + "||";
        if (null != details)
            mesg += details;
        if (null != e)
            mesg += (null != details ? " " : "") + e.getMessage();

        // To be logged
        String logMesg = mesg;

        int nbEntries = e == null ? 20 : 10;
        StringBuilder sb = new StringBuilder(logMesg);
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        boolean first = true;
        for (StackTraceElement el : stackTrace) {
            if (first) { // Skip the 1st element = the 'getStackTrace()' call
                first = false;
                continue;
            }
            if (--nbEntries == 0 || el.getClassName().contains("springframework"))
                break; // we're not interested in the Spring calls, and higher
            sb.append("\n  ").append(el.toString());
        }
        logMesg = sb.toString();

        logger.log(Level.SEVERE, logMesg, e);

        throw new ResponseStatusException(httpStatus, mesg);
    }

    // Confirm that the token is valid and store it in the MDC for logging
    public static void checkAndRecordMDCToken(String tokenId) {
        if (tokenId != null) {
            int offset = tokenId.length();
            if (offset >= 20) throw new InvalidParameterException("Invalid Token Value");

            while(offset != 0) {
                char C = tokenId.charAt(--offset);
                // Token must be composed of Base 64 characters only
                if (!((C >= 'A' && C <= 'Z') || (C >= 'a' && C <= 'z') || (C >= '0' && C <= '9') || C == '+' || C == '/' || C == '_' || C == '-' || C == '=')) {
                    throw new InvalidParameterException("Invalid Token Value");
                }
            }
        } else tokenId = "<null>";
        MDC.put("token", tokenId);
    }

    public static void objectToMDC(Object o) throws IllegalAccessException {
        objectToMDC("", o);
    }

    private static void objectToMDC(String prefix, Object o) throws IllegalAccessException {
        for(Field f : o.getClass().getDeclaredFields()) {
            f.setAccessible(true);
            Object value = f.get(o);
            if (value instanceof List) {
                int count = 0;
                Iterator<?> i = ((List<?>) value).iterator();
                String nameLevel = prefix + f.getName() + "[";
                while(i.hasNext()) objectToMDC(nameLevel + count++ + "].", i.next());
            } else if (value != null) MDC.put(prefix + f.getName(), value.toString());
        }
    }

    // Cleanup malicious inputs. Slow when sanitizing, fast when not
    public static String sanitize(String string, int maxSize) {
        if (string == null) return null;

        int length = string.length();
        if (length <= maxSize) {
            int i = 0;
            while(true) {
                if (i == length) return string;
                char C = string.charAt(i++);
                // All chars between 32 and 126 are printable
                if (C < 32 || C > 126) break;
            }
        } else length = maxSize;

        StringBuilder sb = new StringBuilder(length);
        int i = 0;
        while(i != length) {
            char C = string.charAt(i++);
            if (C < 32 || C > 126) C = '#';
            sb.append(C);
        }

        logger.warning("Sanitized : " + string + " to " + sb.toString());
        return sb.toString();
    }

    public static RemoteDocument getPolicyFile(String fileName) throws IOException {
        InputStream genericIs = null;
        try {
            genericIs = Utils.class.getResourceAsStream("/policy/" + fileName);
            if (genericIs != null) {
                logger.warning("Loaded policy for signature validation : " + fileName);
                return new RemoteDocument(eu.europa.esig.dss.utils.Utils.toByteArray(genericIs), fileName);
            }
        } finally {
            if (genericIs != null) genericIs.close();
        }
        return null;
    }

    public static TrustSources getGetExtraTrustFile(String fileName) throws IOException {
        InputStream genericIs = null;
        try {
            genericIs = Utils.class.getResourceAsStream("/trusts/" + fileName);
            if (genericIs != null) {
                logger.warning("Loaded extra trust : " + fileName);
                byte [] certBytes = genericIs.readAllBytes();
                if (fileName.endsWith(".crt")) certBytes = Base64.getMimeDecoder().decode(certBytes);
                return new TrustSources(null, null, List.of(certBytes));
            }
        } finally {
            if (genericIs != null) genericIs.close();
        }
        return null;
    }
}
