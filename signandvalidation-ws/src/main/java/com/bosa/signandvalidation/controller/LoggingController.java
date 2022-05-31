package com.bosa.signandvalidation.controller;

import java.time.Instant;
import java.util.logging.Level;

import com.bosa.signandvalidation.model.FrontEndErrorReqDTO;
import com.bosa.signandvalidation.model.FrontEndErrorRespDTO;
import com.bosa.signandvalidation.model.FrontEndLogReqDTO;
import com.bosa.signandvalidation.model.FrontEndLogRespDTO;

import org.springframework.web.bind.annotation.*;

import static com.bosa.signandvalidation.exceptions.Utils.getTokenFootprint;
import static com.bosa.signandvalidation.exceptions.Utils.logDateTimeFormatter;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping(value = "/logging")
public class LoggingController extends ControllerBase {

    @GetMapping(value = "/ping", produces = TEXT_PLAIN_VALUE)
    public String ping() {
        return "pong";
    }

    @PostMapping(value = "/error", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public FrontEndErrorRespDTO errorMesg(@RequestBody FrontEndErrorReqDTO feError) {
        String ref = logDateTimeFormatter.format(Instant.now());

        StringBuilder sb = new StringBuilder();
        sb.append(ref).append("||").append(feError.getErr())
            .append(getTokenFootprint(feError.getToken()))
            .append("\nresult: ").append(feError.getResult())
            .append("\nreport: ").append(feError.getReport());

        logger.log(Level.SEVERE, sb.toString());

        return new FrontEndErrorRespDTO(ref);
    }
    @PostMapping(value = "/log", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public FrontEndLogRespDTO logMessage(@RequestBody FrontEndLogReqDTO feLog) {
        String ref = logDateTimeFormatter.format(Instant.now());
        
        StringBuilder sb = new StringBuilder();
        sb.append(ref).append("||")
                .append(getTokenFootprint(feLog.getToken()))
                .append("\nmessage: ").append(feLog.getMessage());
        
        logger.log(feLog.getLevelEnum(), sb.toString());
        
        return new FrontEndLogRespDTO(ref);
    }
}
