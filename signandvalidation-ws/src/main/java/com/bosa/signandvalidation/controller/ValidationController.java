package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.*;
import static com.bosa.signandvalidation.controller.SigningController.authorizeCall;

import com.bosa.signandvalidation.service.TaskService;
import com.bosa.signandvalidation.service.ValidationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

import java.util.List;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@Tag(name = "Electronic signature validation services", description = "See also https://github.com/Fedict/fts-documentation")
@RestController
@RequestMapping(value = "/validation")
public class ValidationController extends ControllerBase {

    @Autowired
    private ValidationService validationService;

    @Autowired
    private TaskService taskService;

    @Value("${features}")
    private String features;

    @GetMapping(value = "/ping", produces = TEXT_PLAIN_VALUE)
    public String ping() {
        return "pong";
    }

    @Operation(summary = "Validate a single document's signatures", description = "Validate a signed file.<BR>" +
            "<BR><B>NOTE : validateSignature calls validaSignatureFull and returns a smaller set of information</B><BR>" +
            "<BR>The Signature can be either part of the signed document or external to the document(s)" +
            "<BR>For external (DETACHED) signature validation a list of 'originalDocument' files must be provided" +
            "<BR>It is possible to check if all signatures have the expected signature level. For this you must set the 'level' value<BR>" +
            "<BR>To allow validation of 'non EIDAs' (Not part of the pan EU PKI) signatures a list of certificates (Either in a '.p12' or a list of '.cer' files)" +
            " can be provided to extend the trusted list of root certificates.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Validation occurred without error. Check the validation results",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = SignatureIndicationsDTO.class)) }),
            @ApiResponse(responseCode = "400", description = "One of the signatures does not match the expected signature level / Error trying to decode the 'trust' certificates or keystore files",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = "/validateSignature", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public SignatureIndicationsDTO validateSignature(@RequestBody DataToValidateDTO toValidate) throws IOException {
        authorizeCall(features, SigningController.Features.validation);
        return validationService.validateSignature(toValidate);
    }

    @Operation(summary = "Validate a single document's signatures", description = "Validate a signed file.<BR>" +
            "<BR><B>NOTE : validateSignature calls validaSignatureFull and returns a smaller set of information</B><BR>" +
            "<BR>The Signature can be either part of the signed document or external to the document(s)" +
            "<BR>For external (DETACHED) signature validation a list of 'originalDocument' files must be provided" +
            "<BR>It is possible to check if all signatures have the expected signature level. For this you must set the 'level' value<BR>" +
            "<BR>To allow validation of 'non EIDAs' (Not part of the pan EU PKI) signatures a list of certificates (Either in a '.p12' or a list of '.cer' files)" +
            " can be provided to extend the trusted list of root certificates.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Validation occurred without error. Check the validation results",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = ASyncTaskDTO.class)) }),
            @ApiResponse(responseCode = "400", description = "One of the signatures does not match the expected signature level / Error trying to decode the 'trust' certificates or keystore files",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = "/validateSignatureASync", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ASyncTaskDTO validateSignatureASync(@RequestBody DataToValidateDTO validateDto) throws IOException {
        authorizeCall(features, SigningController.Features.validation);
        return taskService.addRunningTask(validationService.validateSignatureASync(validateDto), validateDto.getToken());
    }

    @Operation(summary = "Validate a single document's signatures returning all validation reports", description = "Validate a signed file.<BR>" +
            "<BR>The Signature can be either part of the signed document or external to the document(s)" +
            "<BR>For external (DETACHED) signature validation a list of 'originalDocument' files must be provided" +
            "<BR>It is possible to check if all signatures have the expected signature level. For this you must set the 'level' value<BR>" +
            "<BR>To allow validation of 'non EIDAs' (Not part of the pan EU PKI) signatures a list of certificates (Either in a '.p12' or a list of '.cer' files)" +
            " can be provided to extend the trusted list of root certificates.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Validation occurred without error. Check the validation results",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = SignatureFullValiationDTO.class)) }),
            @ApiResponse(responseCode = "400", description = "One of the signatures does not match the expected signature level / Error trying to decode the 'trust' certificates or keystore files",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = "/validateSignatureFull", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public SignatureFullValiationDTO validateSignatureFull(@RequestBody DataToValidateDTO toValidate) {
        authorizeCall(features, SigningController.Features.validation);
        return validationService.validateSignatureFull(toValidate);
    }

    @Operation(summary = "Validate a single certificate", description = "Validate a certificate.<BR>" +
            "<BR><B>NOTE : validateCertificate calls validateCertificateFull and returns a smaller set of information</B><BR>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Validation occurred without error. Check the validation results",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = CertificateIndicationsDTO.class)) }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = "/validateCertificate", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public CertificateIndicationsDTO validateCertificate(@RequestBody CertificateToValidateDTO toValidate) {
        authorizeCall(features, SigningController.Features.validation);
        return validationService.validateCertificate(toValidate);
    }

    @Operation(summary = "Validate a single certificate returning all validation reports", description = "Validate a certificate.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Validation occurred without error. Check the validation results",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = CertificateFullValidationDTO.class)) }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = "/validateCertificateFull", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public CertificateFullValidationDTO validateCertificateFull(@RequestBody CertificateToValidateDTO toValidate) {
        authorizeCall(features, SigningController.Features.validation);
        return validationService.validateCertificateFull(toValidate);
    }

    @Operation(summary = "Validate a list of certificates", description = "Validate a list of certificates returning a list of indications.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Validation occurred without error. Check the validation results",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = IndicationsListDTO.class)) }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = "/validateCertificates", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public IndicationsListDTO validateCertificates(@RequestBody List<CertificateToValidateDTO> toValidateList) {
        authorizeCall(features, SigningController.Features.validation);
        return validationService.validateCertificates(toValidateList);
    }
}
