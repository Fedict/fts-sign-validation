package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.resourcelocator.model.CertificateType;
import com.zetes.projects.bosa.resourcelocator.model.SigningTypeDTO;
import com.zetes.projects.bosa.resourcelocator.model.SigningTypeListDTO;
import com.zetes.projects.bosa.resourcelocator.service.LocatorService;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.common.RemoteDocumentSignatureService;
import eu.europa.esig.dss.ws.signature.dto.DataToSignOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.ExtendDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.SignOneDocumentDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@RestController
@RequestMapping(value = "/signing")
public class SigningController {

    @Autowired
    private LocatorService locatorService;

    @Autowired
    private RemoteDocumentSignatureService remoteDocumentSignatureService;

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
    public ToBeSignedDTO getDataToSign(@RequestBody DataToSignOneDocumentDTO dataToSignDto) {
        return remoteDocumentSignatureService.getDataToSign(dataToSignDto.getToSignDocument(), dataToSignDto.getParameters());
    }

    @PostMapping(value = "/signDocument", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocument(@RequestBody SignOneDocumentDTO signDocumentDto) {
        return remoteDocumentSignatureService.signDocument(signDocumentDto.getToSignDocument(), signDocumentDto.getParameters(), signDocumentDto.getSignatureValue());
    }

    @PostMapping(value = "/extendDocument", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument extendDocument(@RequestBody ExtendDocumentDTO extendDocumentDto) {
        return remoteDocumentSignatureService.extendDocument(extendDocumentDto.getToExtendDocument(), extendDocumentDto.getParameters());
    }

}
