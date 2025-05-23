package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.*;
import com.bosa.signandvalidation.service.*;
import com.bosa.signandvalidation.config.ErrorStrings;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.xml.security.transforms.Transforms;
import org.jetbrains.annotations.NotNull;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.InvalidParameterException;
import java.util.*;
import java.util.concurrent.ExecutionException;

import static com.bosa.signandvalidation.exceptions.Utils.logAndThrowEx;
import static com.bosa.signandvalidation.exceptions.Utils.logger;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.MediaType.*;


@Tag(name = "Electronic signature services", description = "See also https://github.com/Fedict/fts-documentation")
@RestController
@RequestMapping(value = SigningController.ENDPOINT_URL)
public class SigningController extends ControllerBase implements ErrorStrings {

    // Service URL
    public static final String ENDPOINT_URL                     = "/signing";

    public static final String LOGGING_URL                      = "/log";
    public static final String PING_URL                         = "/ping";
    public static final String ERROR_URL                        = "/error";
    public static final String VERSION_URL                      = "/versions";

    // Token operations
    public static final String GET_TASK_RESULT_URL              = "/getTaskResult";
    public static final String GET_TOKEN_FOR_DOCUMENT_URL       = "/getTokenForDocument";
    public static final String GET_TOKEN_FOR_DOCUMENTS_URL      = "/getTokenForDocuments";
    public static final String GET_DATA_TO_SIGN_FOR_TOKEN_URL   = "/getDataToSignForToken";
    public static final String GET_METADATA_FOR_TOKEN_URL       = "/getMetadataForToken";
    public static final String GET_FILE_FOR_TOKEN_URL           = "/getFileForToken";
    public static final String SIGN_DOCUMENT_FOR_TOKEN_URL      = "/signDocumentForToken";

    // standard operations
    public static final String GET_DATA_TO_SIGN_URL                 = "/getDataToSign";
    public static final String GET_DATA_TO_SIGN_MULTIPLE_URL        = "/getDataToSignMultiple";
    public static final String SIGN_DOCUMENT_URL                    = "/signDocument";
    public static final String SIGN_DOCUMENT_ASYNC_URL              = "/signDocumentASync";
    public static final String SIGN_DOCUMENT_MULTIPLE_URL           = "/signDocumentMultiple";
    public static final String SIGN_DOCUMENT_MULTIPLE_ASYNC_URL     = "/signDocumentMultipleASync";
    public static final String EXTEND_DOCUMENT_URL                  = "/extendDocument";
    public static final String EXTEND_DOCUMENT_ASYNC_URL            = "/extendDocumentASync";
    public static final String EXTEND_DOCUMENT_MULTIPLE_URL         = "/extendDocumentMultiple";
    public static final String EXTEND_DOCUMENT_MULTIPLE_ASYNC_URL   = "/extendDocumentMultipleASync";
    public static final String TIMESTAMP_DOCUMENT_URL               = "/timestampDocument";
    public static final String TIMESTAMP_DOCUMENT_MULTIPLE_URL      = "/timestampDocumentMultiple";
    public static final String GET_DATA_TO_SIGN_XADES_MDOC_URL      = "/getDataToSignXades";
    public static final String SIGN_DOCUMENT_XADES_MDOC_URL         = "/signDocumentXades";

    @Autowired
    private SignService signService;

    @Autowired
    private TokenSignService tokenSignService;

    @Autowired
    private TaskService taskService;

    @Value("${features}")
    private String features;

    @GetMapping(value = PING_URL, produces = TEXT_PLAIN_VALUE)
    public String ping() {
        return "pong";
    }

    /*****************************************************************************************
     *
     * TOKEN Signing services
     *
     ****************************************************************************************/

    @Operation(summary = "Get a single document signing flow token", description = "Create signing flow, validate it's parameters and create a unique identifier")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token created and ready for use"),
            @ApiResponse(responseCode = "500", description = "Error while creating the token")
    })
    @PostMapping(value = GET_TOKEN_FOR_DOCUMENT_URL, produces = TEXT_PLAIN_VALUE, consumes = APPLICATION_JSON_VALUE)
    public String getTokenForDocument(@RequestBody GetTokenForDocumentDTO tokenData) {
        authorizeCall(features, Features.token);
        return tokenSignService.getTokenForDocument(tokenData);
    }

    //*****************************************************************************************

    @Operation(summary = "Create a 'signing flow token' for 1 to N documents ", description = "Create signing flow, validate it's parameters and create a unique identifier (Token).<BR>" +
            "This token must be provided in the redirection URL to the BOSA DSS front-end server" +
            "This is the new operation for token creation, future evolutions of the service will only be done on this operation.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token created and ready for use"),
            @ApiResponse(responseCode = "500", description = "Error while creating the token")
    })
    @PostMapping(value = GET_TOKEN_FOR_DOCUMENTS_URL, produces = TEXT_PLAIN_VALUE, consumes = APPLICATION_JSON_VALUE)
    public String getTokenForDocuments(@RequestBody GetTokenForDocumentsDTO gtfd) throws IllegalAccessException {
        authorizeCall(features, Features.token);
        return tokenSignService.getTokenForDocuments(gtfd);
    }

    //*****************************************************************************************

    @Operation(hidden = true)
    @GetMapping(value = GET_METADATA_FOR_TOKEN_URL)
    public DocumentMetadataDTO getMetadataForToken(@RequestParam("token") String tokenString) {
        authorizeCall(features, Features.token);
        return tokenSignService.getMetadataForToken(tokenString);
    }

    //*****************************************************************************************

    @Operation(hidden = true)
    @GetMapping(value = GET_FILE_FOR_TOKEN_URL + "/{token}/{type}/{inputIndexes}")
    public void getFileForToken(@PathVariable("token") String tokenString,
                                @PathVariable GetFileType type,
                                @PathVariable(required = true) Integer inputIndexes[],
                                @RequestParam(required = false)  String forceDownload,
                                HttpServletResponse response) {

        authorizeCall(features, Features.token);
        tokenSignService.getFileForToken(tokenString, type, inputIndexes, forceDownload, response);
    }

    //*****************************************************************************************

    @Operation(hidden = true)
    @PostMapping(value = GET_DATA_TO_SIGN_FOR_TOKEN_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSignForToken(@RequestBody GetDataToSignForTokenDTO dataToSignForTokenDto) {
        authorizeCall(features, Features.token);
        return tokenSignService.getDataToSignForToken(dataToSignForTokenDto);
    }

    //*****************************************************************************************

    @Operation(hidden = true)
    @PostMapping(value = SIGN_DOCUMENT_FOR_TOKEN_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ASyncTaskDTO signDocumentForToken(@RequestBody SignDocumentForTokenDTO signDto) {
        authorizeCall(features, Features.token);
        return taskService.addRunningTask(tokenSignService.signDocumentForTokenAsync(signDto), signDto.getToken());
    }

    //*****************************************************************************************

    @Operation(hidden = true)
    @GetMapping(value = GET_TASK_RESULT_URL + "/{uuid}", produces = APPLICATION_JSON_VALUE)
    public Object getTaskResult(@PathVariable UUID uuid) {
        Object result =  null;
        try {
            logger.info("Task status : " + uuid);
            result =  taskService.getTaskResult(uuid);
        } catch(ExecutionException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof ResponseStatusException) throw (ResponseStatusException)cause;
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, "Task execution " + cause.getMessage());
        } catch(Exception exception) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, "Task management " + exception.getMessage());
        }
        if (result == null) throw new ResponseStatusException(NOT_FOUND);
        return result;
    }

    /*****************************************************************************************
     *
     * NON-TOKEN Signing services
     *
     ****************************************************************************************/

    @Operation(summary = "Calculate the digest of a file to sign", description = "Calculate the digest of a file to sign.<BR>" +
            "This is the first step in a two step process to sign the file")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = DataToSignDTO.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile | Empty mandatory parameter | Invalid PDF signature parameter",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = GET_DATA_TO_SIGN_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSign(@RequestBody GetDataToSignDTO dataToSignDto) {
        authorizeCall(features, Features.signbox);
        return signService.getDataToSign(dataToSignDto);
    }

    //*****************************************************************************************

    @Operation(summary = "Calculate the digest of a list of files to sign", description = "Calculate the digest of a list of files to sign.<BR>" +
            "This is the first step in a two step process to sign the files")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = DataToSignDTO.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile | Empty mandatory parameter",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = GET_DATA_TO_SIGN_MULTIPLE_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSignMultiple(@RequestBody GetDataToSignMultipleDTO dataToSignDto) {
        authorizeCall(features, Features.signbox);
        return signService.getDataToSignMultiple(dataToSignDto);
    }

    //*****************************************************************************************

    @Operation(summary = "Create the signed file based on the signed digest", description = "Create the signed file based on the signed digest.<BR>" +
            "This is the second step in a two step process to sign the file")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = RemoteDocument.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile | Empty mandatory parameter",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = SIGN_DOCUMENT_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocument(@RequestBody SignDocumentDTO signDocumentDto) {
        authorizeCall(features, Features.signbox);
        return signService.signDocument(signDocumentDto);
    }

    //*****************************************************************************************

    @Operation(summary = "Create the signed file based on the signed digest", description = "Create the signed file based on the signed digest.<BR>" +
            "This is the second step in a two step process to sign the file")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = ASyncTaskDTO.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile | Empty mandatory parameter",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = SIGN_DOCUMENT_ASYNC_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ASyncTaskDTO signDocumentASync(@RequestBody SignDocumentDTO signDto) {
        authorizeCall(features, Features.signbox);
        return taskService.addRunningTask(signService.signDocumentASync(signDto), signDto.getToken());
    }

    //*****************************************************************************************

    @Operation(summary = "Create the signed file based on the signed digest", description = "Create a signed file based on the signed digest of a list of files.<BR>" +
            "This is the first step in a two step process to sign the file<BR>" +
            "The signed result will be of the ASIC format<BR>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = RemoteDocument.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile | Empty mandatory parameter",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = SIGN_DOCUMENT_MULTIPLE_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocumentMultiple(@RequestBody SignDocumentMultipleDTO signDocumentDto) {
        authorizeCall(features, Features.signbox);
        return signService.signDocumentMultiple(signDocumentDto);
    }

    //*****************************************************************************************

    @Operation(summary = "Create the signed file based on the signed digest", description = "Create a signed file based on the signed digest of a list of files.<BR>" +
            "This is the first step in a two step process to sign the file<BR>" +
            "The signed result will be of the ASIC format<BR>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = ASyncTaskDTO.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile | Empty mandatory parameter",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = SIGN_DOCUMENT_MULTIPLE_ASYNC_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ASyncTaskDTO signDocumentMultipleAsync(@RequestBody SignDocumentMultipleDTO signDto) {
        authorizeCall(features, Features.signbox);
        return taskService.addRunningTask(signService.signDocumentMultipleASync(signDto), signDto.getToken());
    }

    //*****************************************************************************************

    @Operation(summary = "Extend the signature of a file", description = "Based on a pre-signed file, raise its signature level by adding the 'long term' attributes (OCSP/CRL evidences) or timestamps")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = RemoteDocument.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = EXTEND_DOCUMENT_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument extendDocument(@RequestBody ExtendDocumentDTO extendDocumentDto) {
        authorizeCall(features, Features.signbox);
        return signService.extendDocument(extendDocumentDto);
    }

    //*****************************************************************************************

    @Operation(summary = "Create the signed file based on the signed digest", description = "Create a signed file based on the signed digest of a list of files.<BR>" +
            "This is the first step in a two step process to sign the file<BR>" +
            "The signed result will be of the ASIC format<BR>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = ASyncTaskDTO.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile | Empty mandatory parameter",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = EXTEND_DOCUMENT_ASYNC_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ASyncTaskDTO extendDocumentAsync(@RequestBody ExtendDocumentDTO extDocDto) {
        authorizeCall(features, Features.signbox);
        return taskService.addRunningTask(signService.extendDocumentASync(extDocDto), extDocDto.getToken());
    }

    //*****************************************************************************************

    @Operation(summary = "Extend the signature of a list of files", description = "Based on an existing signature, raise its signature level by adding the 'long term' attributes (OCSP/CRL evidences) or timestamps")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = RemoteDocument.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = EXTEND_DOCUMENT_MULTIPLE_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument extendDocumentMultiple(@RequestBody ExtendDocumentDTO extendDocumentDto) {
        authorizeCall(features, Features.signbox);
        return signService.extendDocumentMultiple(extendDocumentDto);
    }

    //*****************************************************************************************

    @Operation(summary = "Create the signed file based on the signed digest", description = "Create a signed file based on the signed digest of a list of files.<BR>" +
            "This is the first step in a two step process to sign the file<BR>" +
            "The signed result will be of the ASIC format<BR>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = ASyncTaskDTO.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile | Empty mandatory parameter",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = EXTEND_DOCUMENT_MULTIPLE_ASYNC_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ASyncTaskDTO extendDocumentMultipleASync(@RequestBody ExtendDocumentDTO extDocDto) {
        authorizeCall(features, Features.signbox);
        return taskService.addRunningTask(signService.extendDocumentMultipleASync(extDocDto), extDocDto.getToken());
    }

    //*****************************************************************************************

    @Operation(summary = "Timestamp a file")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = RemoteDocument.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = TIMESTAMP_DOCUMENT_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument timestampDocument(@RequestBody TimestampDocumentDTO timestampDocumentDto) {
        authorizeCall(features, Features.signbox);
        return signService.timestampDocument(timestampDocumentDto);
    }

    //*****************************************************************************************

    @Operation(summary = "Timestamp a list of files and produce a file in ASIC format")
    @PostMapping(value = TIMESTAMP_DOCUMENT_MULTIPLE_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument timestampDocumentMultiple(@RequestBody TimestampDocumentMultipleDTO timestampDocumentDto) {
        authorizeCall(features, Features.signbox);
        return signService.timestampDocumentMultiple(timestampDocumentDto);
    }

    //*****************************************************************************************

    @Operation(summary = "Calculate the digest of a file to sign as Xades Internally detached", description = "Calculate the digest of a file to sign as Xades Internally detached.<BR>" +
            "This is the second step in a two step process to sign the file")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = DataToSignDTO.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile | Empty mandatory parameter | Invalid PDF signature parameter",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = GET_DATA_TO_SIGN_XADES_MDOC_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSignXades(@RequestBody GetDataToSignXMLElementsDTO getDataToSignDto) {
        authorizeCall(features, Features.signbox);
        return signService.getDataToSignXades(getDataToSignDto);
    }

    //*****************************************************************************************

    @Operation(summary = "Create the signed file as Xades Internally detached based on the signed digest", description = "Create the signed file as Xades Internally detached based on the signed digest.<BR>" +
            "This is the second step in a two step process to sign the file")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = RemoteDocument.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile | Empty mandatory parameter",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = SIGN_DOCUMENT_XADES_MDOC_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocumentXades(@RequestBody SignXMLElementsDTO signDto) {
        authorizeCall(features, Features.signbox);
        return signService.signDocumentXades(signDto);
    }

    //*****************************************************************************************

    enum Features {
        validation,token,signbox
    }

    //*****************************************************************************************

    public static void authorizeCall(String features, Features feature) {
        if (features != null && !features.contains(feature.name())) throw new InvalidParameterException("Unknown Operation");
    }

    //*****************************************************************************************
}
