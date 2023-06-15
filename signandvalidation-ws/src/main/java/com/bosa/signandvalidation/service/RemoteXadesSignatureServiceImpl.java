package com.bosa.signandvalidation.service;

import eu.europa.esig.dss.model.*;
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

import java.util.List;
import java.util.Objects;

/**
 * The remote signature service implementation with support for XML references
 */
@SuppressWarnings("serial")
public class RemoteXadesSignatureServiceImpl extends RemoteDocumentSignatureServiceImpl {

    private static final Logger LOG = LoggerFactory.getLogger(RemoteXadesSignatureServiceImpl.class);

    /** XAdES signature service */
    private XAdESService xadesService;

    /**
     * Sets the XAdES signature service
     *
     * @param xadesService {@link XAdESService}
     */
    public void setXadesServiceWithReferences(XAdESService xadesService) {
        this.xadesService = xadesService;
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public ToBeSignedDTO getDataToSignWithReferences(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters, List<DSSReference> refs) {
        if (refs == null) {
            return getDataToSign(remoteDocument, remoteParameters);
        }

        Objects.requireNonNull(remoteDocument, "remoteDocument must be defined!");
        Objects.requireNonNull(remoteParameters, "remoteParameters must be defined!");
        Objects.requireNonNull(remoteParameters.getSignatureLevel(), "signatureLevel must be defined!");
        LOG.info("GetDataToSign in process...");
        SerializableSignatureParameters parameters = createParameters(remoteParameters);
        DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);
        ((XAdESSignatureParameters)parameters).setReferences(refs);
        for(DSSReference ref : refs) {
            ref.setContents(dssDocument);
        }
        ToBeSigned dataToSign = ((DocumentSignatureService)xadesService).getDataToSign(dssDocument, parameters);
        LOG.info("GetDataToSign is finished");
        return DTOConverter.toToBeSignedDTO(dataToSign);
    }

    public RemoteDocument signDocumentWithReferences(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters, SignatureValueDTO signatureValueDTO, List<DSSReference> refs) {
        if (refs == null) {
            return signDocument(remoteDocument, remoteParameters, signatureValueDTO);
        }

        Objects.requireNonNull(remoteDocument, "remoteDocument must be defined!");
        Objects.requireNonNull(remoteParameters, "remoteParameters must be defined!");
        Objects.requireNonNull(remoteParameters.getSignatureLevel(), "signatureLevel must be defined!");
        LOG.info("SignDocument in process...");
        SerializableSignatureParameters parameters = createParameters(remoteParameters);
        DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);
        ((XAdESSignatureParameters)parameters).setReferences(refs);
        for(DSSReference ref : refs) {
            ref.setContents(dssDocument);
        }

        DSSDocument signDocument = ((DocumentSignatureService)xadesService).signDocument(dssDocument, parameters, toSignatureValue(signatureValueDTO));
        LOG.info("SignDocument is finished");
        return RemoteDocumentConverter.toRemoteDocument(signDocument);
    }
}
