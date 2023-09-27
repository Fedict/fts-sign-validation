package com.bosa.signandvalidation.exceptions;

import com.bosa.signandvalidation.controller.SigningController;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.security.InvalidParameterException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
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
        if (null == e) {
            // No exception to be logged -> add the start of the stack trace to the log
            StringBuilder sb = new StringBuilder();
            sb.append(logMesg);
            StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
            boolean first = true;
            for (StackTraceElement el : stackTrace) {
                if (first) { // Skip the 1st element = the 'getStackTrace()' call
                    first = false;
                    continue;
                }
                if (el.getClassName().contains("springframework"))
                    break; // we're not interested in the Spring calls, and higher
                sb.append("\n  ").append(el.toString());
            }
            logMesg = sb.toString();
        }
        logger.log(Level.SEVERE, logMesg, e);

        throw new ResponseStatusException(httpStatus, mesg);
    }

    // Confirm that the token is valid and store it in the MDC for logging
    public static void checkAndRecordMDCToken(String tokenId) {
        if (tokenId != null) {
            int offset = tokenId.length();
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

    // Clear the token in the MDC to avoid polluting non-token logs with leftover token value
    public static void clearMDCToken() {
        MDC.remove("token");
    }
}
