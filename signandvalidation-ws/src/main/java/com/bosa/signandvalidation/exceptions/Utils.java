package com.bosa.signandvalidation.exceptions;

import com.bosa.signandvalidation.controller.SigningController;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

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
        if (null != token)
            logMesg += getTokenFootprint(token);
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

    // The applicative logging system is used to track signature processes through the last 8 chars of the token
    public static String getTokenFootprint(String token) {
        String footprint = token;
        if (null != token) {
            int len = token.length();
            if (len >= 8) footprint = "..." + token.substring(len - 8, len);
        } else footprint = "<null>";

        MDC.MDCCloseable mdc = MDC.putCloseable("token", footprint);
        return " token=" + footprint;
    }
}
