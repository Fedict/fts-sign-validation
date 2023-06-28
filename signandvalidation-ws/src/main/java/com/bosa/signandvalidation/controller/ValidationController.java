package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.config.ThreadedCertificateVerifier;
import com.bosa.signandvalidation.exceptions.IllegalSignatureFormatException;
import com.bosa.signandvalidation.model.*;
import com.bosa.signandvalidation.service.ReportsService;
import com.bosa.signandvalidation.service.BosaRemoteDocumentValidationService;
import com.bosa.signandvalidation.config.ErrorStrings;

import static com.bosa.signandvalidation.exceptions.Utils.logAndThrowEx;
import static eu.europa.esig.dss.enumerations.Indication.PASSED;

import eu.europa.esig.dss.diagnostic.jaxb.*;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.ws.cert.validation.common.RemoteCertificateValidationService;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@RestController
@RequestMapping(value = "/validation")
public class ValidationController extends ControllerBase implements ErrorStrings {

    @Autowired
    private BosaRemoteDocumentValidationService remoteDocumentValidationService;

    @Autowired
    private RemoteCertificateValidationService remoteCertificateValidationService;

    @Autowired
    private ReportsService reportsService;

    @GetMapping(value = "/ping", produces = TEXT_PLAIN_VALUE)
    public String ping() {
        return "pong";
    }

    @Operation(summary = "Validate a single document's signatures", description = "Validate a signed file.<BR>" +
            "<BR><B>NOTE : validaSignature calls validaSignatureFull and returns a smaller set of information</B><BR>" +
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
        SignatureFullValiationDTO report = validateSignatureFull(toValidate);
        SignatureIndicationsDTO signDto = reportsService.getSignatureIndicationsAndReportsDto(report);
        logger.info("ValidateSignature is finished");
        return signDto;
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
        if (toValidate.getSignedDocument() == null)
            logAndThrowEx(BAD_REQUEST, NO_DOC_TO_VALIDATE, null, null);

        try {
            if (toValidate.getTrust() != null) {
                ThreadedCertificateVerifier.setExtraCertificateSource(getCertificateSource(toValidate.getTrust()));
            }

            SignatureFullValiationDTO reportsDto = remoteDocumentValidationService.validateDocument(toValidate.getSignedDocument(), toValidate.getOriginalDocuments(), toValidate.getPolicy());
            if (toValidate.getLevel() != null && reportsDto.getDiagnosticData() != null) {
                checkSignatures(toValidate.getLevel(), reportsDto);
            }
            logger.info("ValidateSignatureFull is finished");
            return reportsDto;
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } catch (IllegalSignatureFormatException e) {
            logAndThrowEx(BAD_REQUEST, INVALID_SIGNATURE_LEVEL, e);
        } catch (CertificateException|IOException|NoSuchAlgorithmException|KeyStoreException e) {
            // Exceptions linked to getCertificateSource keystore manipulation
            logAndThrowEx(BAD_REQUEST, INVALID_PARAM, e);
        } finally {
            ThreadedCertificateVerifier.clearExtraCertificateSource(); // Cleanup
        }
        return null; // We won't get here
    }

    // The below password is only needed because, pre-Java 20 JVM, a "null" password keystore
    // ignores the certificates added to it. With Java 20 they are accepted.
    // This hardcoded password will of course trigger security review (sast or human)... although it should not since
    // the keystore is only held in memory (although not in "unswapaable" memory... but that is another topic)
    private static final String SILLY_PASSWORD = "123456";
    private CertificateSource getCertificateSource(KeystoreOrCerts trust) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {

        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        if (trust.getKeystore() != null) {
            String password = trust.getPassword();
            InputStream keyStoreStream = new ByteArrayInputStream(trust.getKeystore());
            KeyStoreCertificateSource keystoreCrtSrc = new KeyStoreCertificateSource(keyStoreStream, "PKCS12", password);
            trustedCertificateSource.importAsTrusted(keystoreCrtSrc);
        }

        if (trust.getCerts() != null) {
            // Ideally we should be able to add "cert" like this:
            //
            //		KeyStoreCertificateSource keystore = new KeyStoreCertificateSource("PKCS12", null);
            //		CertificateToken certificateToken = new CertificateToken(cert);
            //		keystore.addCertificate(certificateToken);
            //
            // but because "KeyStoreCertificateSource.importAsTrusted" depends on cert  aliases and CertificateToken doesn't set aliases
            // we're forced to use the inefficient code below : creating a keystore, add the cert (with alias ;-) ) , marshal the keystore and
            // unmarshal it as a KeyStoreCertificateSource
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            int count = 0;
            for(byte[] certBytes : trust.getCerts()) {
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                keyStore.setCertificateEntry("alias_" + Integer.toString(count++), cert);
            }
            ByteArrayOutputStream baos = new ByteArrayOutputStream(1000);

            keyStore.store(baos, SILLY_PASSWORD.toCharArray());
            InputStream keyStoreStream = new ByteArrayInputStream(baos.toByteArray());
            KeyStoreCertificateSource keystoreCrtSrc = new KeyStoreCertificateSource(keyStoreStream, "PKCS12", SILLY_PASSWORD);
            trustedCertificateSource.importAsTrusted(keystoreCrtSrc);
        }

        return trustedCertificateSource;
    }


    private void checkSignatures(SignatureLevel level, SignatureFullValiationDTO reportsDto) throws IllegalSignatureFormatException {
        List<XmlSignature> signatures = reportsDto.getDiagnosticData().getSignatures();
        if (signatures != null)  {
            for (XmlSignature signature : signatures) {
                if (!level.equals(signature.getSignatureFormat())) {
                    throw new IllegalSignatureFormatException("Was : " + signature.getSignatureFormat() + ", expected :" + level);
                }
            }
        }
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
        if (toValidate.getCertificate() == null)
            logAndThrowEx(BAD_REQUEST, NO_CERT_TO_VALIDATE, null, null);

        try {
            CertificateReportsDTO certificateReportsDTO = remoteCertificateValidationService.validateCertificate(
                    new eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO(
                            toValidate.getCertificate(), toValidate.getCertificateChain(), toValidate.getValidationTime()));
            CertificateIndicationsDTO rv = reportsService.getCertificateIndicationsDTO(certificateReportsDTO, toValidate.getExpectedKeyUsage());
            if(rv.getIndication() != PASSED) {
                certificateReportsDTO.getSimpleCertificateReport().getChain().forEach(item -> {
                    logger.log(Level.SEVERE, "Certificate validation indication = {0}; certificate ID = {1}, issuer ID = {2}", new Object[]{rv.getIndication().toString(), item.getId(), item.getIssuerId()});
                });
            }
            logger.info("ValidateCertificate is finished");
            return rv;
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
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
        if (toValidate.getCertificate() == null)
            logAndThrowEx(BAD_REQUEST, NO_CERT_TO_VALIDATE, null, null);

        try {
            CertificateReportsDTO result = remoteCertificateValidationService.validateCertificate(
                new eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO(
			        toValidate.getCertificate(), toValidate.getCertificateChain(), toValidate.getValidationTime()));
            logger.info("ValidateCertificateFull is finished");

            return new CertificateFullValidationDTO(result.getDiagnosticData(), result.getSimpleCertificateReport(), result.getDetailedReport());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
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
        try {
            List<CertificateIndicationsDTO> indications = new ArrayList<>();

            for (CertificateToValidateDTO toValidate : toValidateList) {
                indications.add(validateCertificate(toValidate));
            }

            logger.info("ValidateCertificates is finished");
            return new IndicationsListDTO(indications);
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }
}
