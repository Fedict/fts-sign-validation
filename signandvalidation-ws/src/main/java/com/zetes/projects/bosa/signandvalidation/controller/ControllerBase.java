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
        logAndThrowEx(httpStatus, errConst, null, e);
    }

    protected void logAndThrowEx(HttpStatus httpStatus, String errConst, String details) {
        logAndThrowEx(httpStatus, errConst, details, null);
    }

    protected void logAndThrowEx(HttpStatus httpStatus, String errConst, String details, Exception e) {
        if (e instanceof ResponseStatusException)
            throw (ResponseStatusException) e; // we already logged this exception

        String ref = logDateTimeFormatter.format(Instant.now());
        String mesg = ref + "||" + errConst + "||";
        if (null != details)
            mesg += details;
        if (null != e)
            mesg += (null != details ? " " : "") + e.getMessage();

        String logMesg = mesg;
        if (null == e) {
            // No exception to be logged -> add the start of the stack trace to the log
            StringBuilder sb = new StringBuilder();
            sb.append(mesg);
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
}
