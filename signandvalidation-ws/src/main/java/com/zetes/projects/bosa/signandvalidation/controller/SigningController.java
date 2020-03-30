package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.resourcelocator.model.CertificateType;
import com.zetes.projects.bosa.resourcelocator.model.SigningTypeDTO;
import com.zetes.projects.bosa.resourcelocator.model.SigningTypeListDTO;
import com.zetes.projects.bosa.resourcelocator.service.LocatorService;
import com.zetes.projects.bosa.signandvalidation.model.ExtendDocumentDTO;
import com.zetes.projects.bosa.signandvalidation.model.GetDataToSignDTO;
import com.zetes.projects.bosa.signandvalidation.model.SignDocumentDTO;
import com.zetes.projects.bosa.signandvalidation.service.ReportsService;
import com.zetes.projects.bosa.signingconfigurator.exception.NullParameterException;
import com.zetes.projects.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.zetes.projects.bosa.signingconfigurator.exception.SignatureAlgoNotSupportedException;
import com.zetes.projects.bosa.signingconfigurator.service.SigningConfiguratorService;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.common.RemoteDocumentSignatureService;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.validation.common.RemoteDocumentValidationService;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@RestController
@RequestMapping(value = "/signing")
public class SigningController {

    @Autowired
    private LocatorService locatorService;

    @Autowired
    private SigningConfiguratorService signingConfigService;

    @Autowired
    private RemoteDocumentSignatureService signatureService;

    @Autowired
    private RemoteDocumentValidationService validationService;

    @Autowired
    private ReportsService reportsService;

    @GetMapping(value = "/ping", produces = TEXT_PLAIN_VALUE)
    public String ping() {
        return "pong";
    }

    @GetMapping(value = "/getSigningType/{name}", produces = APPLICATION_JSON_VALUE)
    public SigningTypeDTO getSigningType(@PathVariable String name) {
        SigningTypeDTO signingTypeByName = locatorService.getSigningTypeByName(name);
        if (signingTypeByName != null) {
            return signingTypeByName;
        } else {
            throw new ResponseStatusException(NOT_FOUND, String.format("Signing type %s not found", name));
        }
    }

    @GetMapping(value = "/getSigningTypes/{certificateType}", produces = APPLICATION_JSON_VALUE)
    public SigningTypeListDTO getSigningTypes(@PathVariable CertificateType certificateType) {
        return locatorService.getSigningTypesByCertificateType(certificateType);
    }

    @PostMapping(value = "/getDataToSign", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ToBeSignedDTO getDataToSign(@RequestBody GetDataToSignDTO dataToSignDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParameters(
                    dataToSignDto.getSigningProfileId(),
                    dataToSignDto.getClientSignatureParameters()
            );

            return signatureService.getDataToSign(dataToSignDto.getToSignDocument(), parameters);
        } catch (ProfileNotFoundException | SignatureAlgoNotSupportedException | NullParameterException e) {
            throw new ResponseStatusException(BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping(value = "/signDocument", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocument(@RequestBody SignDocumentDTO signDocumentDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParameters(
                    signDocumentDto.getSigningProfileId(),
                    signDocumentDto.getClientSignatureParameters()
            );

            RemoteDocument signedDoc = signatureService.signDocument(signDocumentDto.getToSignDocument(), parameters, signDocumentDto.getSignatureValue());

            WSReportsDTO reportsDto = validationService.validateDocument(signedDoc, null, null);

            if (reportsService.isValidSignature(reportsDto)) {
                return signedDoc;
            } else {
                Indication indication = reportsService.getIndication(reportsDto);
                SubIndication subIndication = reportsService.getSubIndication(reportsDto);
                throw new ResponseStatusException(BAD_REQUEST, String.format("Signed document did not pass validation: %s, %s", indication, subIndication));
            }
        } catch (ProfileNotFoundException | SignatureAlgoNotSupportedException | NullParameterException e) {
            throw new ResponseStatusException(BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping(value = "/extendDocument", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument extendDocument(@RequestBody ExtendDocumentDTO extendDocumentDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getExtensionParameters(
                    extendDocumentDto.getExtendProfileId(),
                    extendDocumentDto.getDetachedContents()
            );

            RemoteDocument extendedDoc = signatureService.extendDocument(extendDocumentDto.getToExtendDocument(), parameters);

            WSReportsDTO reportsDto = validationService.validateDocument(extendedDoc, null, null);

            if (reportsService.isValidSignature(reportsDto)) {
                return extendedDoc;
            } else {
                Indication indication = reportsService.getIndication(reportsDto);
                SubIndication subIndication = reportsService.getSubIndication(reportsDto);
                throw new ResponseStatusException(BAD_REQUEST, String.format("Signed document did not pass validation: %s, %s", indication, subIndication));
            }
        } catch (ProfileNotFoundException | NullParameterException e) {
            throw new ResponseStatusException(BAD_REQUEST, e.getMessage());
        }
    }

}
