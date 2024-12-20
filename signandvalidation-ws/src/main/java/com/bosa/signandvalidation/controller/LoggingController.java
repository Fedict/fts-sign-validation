package com.bosa.signandvalidation.controller;

import java.time.Instant;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.bosa.signandvalidation.model.*;

import io.swagger.v3.oas.annotations.Operation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import static com.bosa.signandvalidation.controller.SigningController.*;
import static com.bosa.signandvalidation.exceptions.Utils.*;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping(value = "/logging")
public class LoggingController extends ControllerBase {

    @Value("${application.version}")
    private String applicationVersion;

    protected final Logger logger = Logger.getLogger(LoggingController.class.getName());

    @Operation(hidden = true)
    @GetMapping(value = PING_URL, produces = TEXT_PLAIN_VALUE)
    public String ping() {
        return "pong";
    }

    @Operation(hidden = true)
    @PostMapping(value = ERROR_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public FrontEndErrorRespDTO errorMesg(@RequestBody FrontEndErrorReqDTO feError) {
        checkAndRecordMDCToken(feError.getToken());
        feError.sanitize();
        String ref = logDateTimeFormatter.format(Instant.now());

        StringBuilder sb = new StringBuilder();
        sb.append(ref).append("||").append(feError.getErr())
            .append("\nresult: ").append(feError.getResult())
            .append("\nreport: ").append(feError.getReport());

        logger.log(Level.SEVERE, sb.toString());

        return new FrontEndErrorRespDTO(ref);
    }
    @Operation(hidden = true)
    @PostMapping(value = LOGGING_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public FrontEndLogRespDTO logMessage(@RequestBody FrontEndLogReqDTO feLog) {
        checkAndRecordMDCToken(feLog.getToken());
        feLog.sanitize();
        String ref = logDateTimeFormatter.format(Instant.now());

        StringBuilder sb = new StringBuilder();
        sb.append(ref).append("||").append("message: ").append(feLog.getMessage());
        logger.log(feLog.getLevelEnum(), sb.toString());

        return new FrontEndLogRespDTO(ref);
    }

    @Operation(hidden = true)
    @PostMapping(value = VERSION_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public String logVersion(@RequestBody VersionLogReqDTO versionLog) throws IllegalAccessException {
        checkAndRecordMDCToken(versionLog.getToken());
        versionLog.sanitize();
        versionLog.setToken(null);
        objectToMDC(versionLog);
        logger.warning("Versions");
        return applicationVersion;
    }
}
