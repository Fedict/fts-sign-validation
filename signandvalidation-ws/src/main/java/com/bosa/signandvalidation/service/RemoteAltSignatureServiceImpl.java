package com.bosa.signandvalidation.service;

import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.common.RemoteDocumentSignatureServiceImpl;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidParameterException;
import java.util.List;
import java.util.Objects;

/**
 * The remote signature service implementation with support for PADES "appName" and XADES with internal references
 */
@SuppressWarnings("serial")
public class RemoteAltSignatureServiceImpl extends RemoteDocumentSignatureServiceImpl {

    private static final Logger LOG = LoggerFactory.getLogger(RemoteAltSignatureServiceImpl.class);

    private PAdESService padesService;
    private XAdESService xadesService;

    public void setAltXadesService(XAdESService xadesService) { this.xadesService = xadesService; }

    public void setAltPadesService(PAdESService padesService) { this.padesService = padesService; }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public ToBeSignedDTO altGetDataToSign(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters, List<DSSReference> refs, String applicationName) {

        SignatureForm form = remoteParameters.getSignatureLevel().getSignatureForm();
        if (!SignatureForm.PAdES.equals(form) && refs == null) {
            // fallback to standard getDataToSign for non-custom signatures
            return getDataToSign(remoteDocument, remoteParameters);
        }

        Objects.requireNonNull(remoteDocument, "remoteDocument must be defined!");
        Objects.requireNonNull(remoteParameters, "remoteParameters must be defined!");
        Objects.requireNonNull(remoteParameters.getSignatureLevel(), "signatureLevel must be defined!");
        LOG.info("altGetDataToSign in process...");
        SerializableSignatureParameters parameters = this.createParameters(remoteParameters);
        DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);

        ToBeSigned dataToSign;
        DocumentSignatureService signatureService;
        if (refs == null) {
            ((PAdESSignatureParameters)parameters).setAppName(applicationName);
            signatureService = padesService;
        } else {
            if (!SignatureForm.XAdES.equals(form)) throw new InvalidParameterException("Internally detached signatures only for Xades");

            ((XAdESSignatureParameters)parameters).setReferences(refs);
            for(DSSReference ref : refs) ref.setContents(dssDocument);
            signatureService = xadesService;
        }

        dataToSign = signatureService.getDataToSign(dssDocument, parameters);
        LOG.info("altGetDataToSign is finished");
        return DTOConverter.toToBeSignedDTO(dataToSign);
    }

    public RemoteDocument altSignDocument(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters, SignatureValueDTO signatureValueDTO, List<DSSReference> refs, String applicationName) {
        SignatureForm form = remoteParameters.getSignatureLevel().getSignatureForm();
        if (!SignatureForm.PAdES.equals(form) && refs == null) {
            // fallback to standard getDataToSign for non-custom signatures
            return signDocument(remoteDocument, remoteParameters, signatureValueDTO);
        }

        Objects.requireNonNull(remoteDocument, "remoteDocument must be defined!");
        Objects.requireNonNull(remoteParameters, "remoteParameters must be defined!");
        Objects.requireNonNull(remoteParameters.getSignatureLevel(), "signatureLevel must be defined!");
        LOG.info("altSignDocument in process...");
        SerializableSignatureParameters parameters = createParameters(remoteParameters);
        DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);

        DocumentSignatureService signatureService;
        if (refs == null) {
            ((PAdESSignatureParameters)parameters).setAppName(applicationName);
            signatureService = padesService;
        } else {
            if (!SignatureForm.XAdES.equals(form)) throw new InvalidParameterException("Internally detached signatures only for Xades");
            ((XAdESSignatureParameters)parameters).setReferences(refs);
            for(DSSReference ref : refs) ref.setContents(dssDocument);
            signatureService = xadesService;
        }

        DSSDocument signDocument = signatureService.signDocument(dssDocument, parameters, toSignatureValue(signatureValueDTO));
        LOG.info("altSignDocument is finished");
        return RemoteDocumentConverter.toRemoteDocument(signDocument);
    }
}
