package com.bosa.signandvalidation.controller;

import java.time.Instant;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.bosa.signandvalidation.model.*;

import io.swagger.v3.oas.annotations.Operation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import static com.bosa.signandvalidation.exceptions.Utils.logDateTimeFormatter;
import static com.bosa.signandvalidation.exceptions.Utils.checkAndRecordMDCToken;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping(value = "/logging")
public class LoggingController extends ControllerBase {

    @Value("${application.version}")
    private String applicationVersion;

    protected final Logger logger = Logger.getLogger(LoggingController.class.getName());

    @Operation(hidden = true)
    @GetMapping(value = "/ping", produces = TEXT_PLAIN_VALUE)
    public String ping() {
        return "pong";
    }

    @Operation(hidden = true)
    @PostMapping(value = "/error", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public FrontEndErrorRespDTO errorMesg(@RequestBody FrontEndErrorReqDTO feError) {
        String ref = logDateTimeFormatter.format(Instant.now());
        checkAndRecordMDCToken(feError.getToken());

        StringBuilder sb = new StringBuilder();
        sb.append(ref).append("||").append(feError.getErr())
            .append("\nresult: ").append(feError.getResult())
            .append("\nreport: ").append(feError.getReport());

        logger.log(Level.SEVERE, sb.toString());

        return new FrontEndErrorRespDTO(ref);
    }
    @Operation(hidden = true)
    @PostMapping(value = "/log", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public FrontEndLogRespDTO logMessage(@RequestBody FrontEndLogReqDTO feLog) {
        String ref = logDateTimeFormatter.format(Instant.now());
        checkAndRecordMDCToken(feLog.getToken());

        StringBuilder sb = new StringBuilder();
        String msg = feLog.getMessage();
        if (msg.startsWith("Version")) msg += "Coucou";
        sb.append(ref).append("||").append("message: ").append(msg);
        logger.log(feLog.getLevelEnum(), sb.toString());

        return new FrontEndLogRespDTO(ref);
    }

    @Operation(hidden = true)
    @PostMapping(value = "/versions", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public String logVersion(@RequestBody VersionLogReqDTO versionLog) {
        checkAndRecordMDCToken(versionLog.getToken());
        logger.warning("Versions -> Backend:" + applicationVersion +
                " - FrontEndType: " + versionLog.getFrontEndType() +
                " - FrontEnd: " + versionLog.getFrontEnd() +
                " - BEID: " + versionLog.getBeID() +
                " - Browser extension : " + versionLog.getBrowserExt() +
                " - Browser store: " + versionLog.getBrowserStore());
        return applicationVersion;
    }
}
