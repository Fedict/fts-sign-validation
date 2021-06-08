package com.zetes.projects.bosa.signandvalidation.controller;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.logging.Logger;
import java.util.logging.Level;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/** Base class for the real Controller classes in this dir; provides logging and exception handling */
class ControllerBase {
    protected static DateTimeFormatter logDateTimeFormatter = 
        DateTimeFormatter.ofPattern("yyyyMMddHHmmssSSS").withZone(ZoneId.systemDefault());

    protected Logger logger = Logger.getLogger(SigningController.class.getName());

    protected void logAndThrowEx(HttpStatus httpStatus, String errConst, Exception e) {
        logAndThrowEx(null, httpStatus, errConst, null, e);
    }

    protected void logAndThrowEx(HttpStatus httpStatus, String errConst, String details) {
        logAndThrowEx(null, httpStatus, errConst, details, null);
    }

    protected void logAndThrowEx(HttpStatus httpStatus, String errConst, String details, Exception e) {
        logAndThrowEx(null, httpStatus, errConst, details, e);
    }

    protected void logAndThrowEx(String token, HttpStatus httpStatus, String errConst, Exception e) {
        logAndThrowEx(token, httpStatus, errConst, null, e);
    }

    protected void logAndThrowEx(String token, HttpStatus httpStatus, String errConst, String details) {
        logAndThrowEx(token, httpStatus, errConst, details, null);
    }

    protected void logAndThrowEx(String token, HttpStatus httpStatus, String errConst, String details, Exception e) {
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
            logMesg += token2str(token);
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

    protected String token2str(String token) {
        if (null == token)
            return " token=<null>"; // shouldn't happen
        int len = token.length();
        if (len < 8)
            return " token=" + token; // shouldn't happen
        return " token=..." + token.substring(len - 8, len);
    }
}
