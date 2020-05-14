package com.zetes.projects.bosa.signandvalidation.service;

import com.zetes.projects.bosa.signingconfigurator.model.ExtendedRemoteSignatureParameters;
import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.common.AbstractRemoteSignatureServiceImpl;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DocumentSignatureService extends AbstractRemoteSignatureServiceImpl {

    private static final Logger LOG = LoggerFactory.getLogger(DocumentSignatureService.class);

    private eu.europa.esig.dss.signature.DocumentSignatureService xadesService;

    private eu.europa.esig.dss.signature.DocumentSignatureService cadesService;

    private eu.europa.esig.dss.signature.DocumentSignatureService padesService;

    private eu.europa.esig.dss.signature.DocumentSignatureService asicWithXAdESService;

    private eu.europa.esig.dss.signature.DocumentSignatureService asicWithCAdESService;

    public void setXadesService(eu.europa.esig.dss.signature.DocumentSignatureService xadesService) {
        this.xadesService = xadesService;
    }

    public void setCadesService(eu.europa.esig.dss.signature.DocumentSignatureService cadesService) {
        this.cadesService = cadesService;
    }

    public void setPadesService(eu.europa.esig.dss.signature.DocumentSignatureService padesService) {
        this.padesService = padesService;
    }

    public void setAsicWithXAdESService(eu.europa.esig.dss.signature.DocumentSignatureService asicWithXAdESService) {
        this.asicWithXAdESService = asicWithXAdESService;
    }

    public void setAsicWithCAdESService(eu.europa.esig.dss.signature.DocumentSignatureService asicWithCAdESService) {
        this.asicWithCAdESService = asicWithCAdESService;
    }

    @SuppressWarnings("rawtypes")
    private eu.europa.esig.dss.signature.DocumentSignatureService getServiceForSignature(RemoteSignatureParameters parameters) {
        ASiCContainerType asicContainerType = parameters.getAsicContainerType();
        SignatureLevel signatureLevel = parameters.getSignatureLevel();
        SignatureForm signatureForm = signatureLevel.getSignatureForm();
        if (asicContainerType != null) {
            switch (signatureForm) {
                case XAdES:
                    return asicWithXAdESService;
                case CAdES:
                    return asicWithCAdESService;
                default:
                    throw new DSSException("Unrecognized format (XAdES or CAdES are allowed with ASiC) : " + signatureForm);
            }
        } else {
            switch (signatureForm) {
                case XAdES:
                    return xadesService;
                case CAdES:
                    return cadesService;
                case PAdES:
                    return padesService;
                default:
                    throw new DSSException("Unrecognized format " + signatureLevel);
            }
        }
    }

    protected AbstractSignatureParameters createParameters(ExtendedRemoteSignatureParameters remoteParameters) {
        AbstractSignatureParameters parameters = null;
        ASiCContainerType asicContainerType = remoteParameters.getAsicContainerType();
        SignatureForm signatureForm = remoteParameters.getSignatureLevel().getSignatureForm();
        if (asicContainerType != null) {
            parameters = getASiCSignatureParameters(asicContainerType, signatureForm);
        } else {
            switch (signatureForm) {
                case CAdES:
                    parameters = new CAdESSignatureParameters();
                    break;
                case PAdES:
                    parameters = createPadesSignatureParams(remoteParameters);
                    break;
                case XAdES:
                    parameters = new XAdESSignatureParameters();
                    break;
                default:
                    throw new DSSException("Unsupported signature form : " + signatureForm);
            }
        }

        fillParameters(parameters, remoteParameters);

        return parameters;
    }

    private PAdESSignatureParameters createPadesSignatureParams(ExtendedRemoteSignatureParameters remoteParameters) {
        PAdESSignatureParameters padesParams = new PAdESSignatureParameters();
        padesParams.setSignatureSize(9472 * 2); // double reserved space for signature

        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setText(remoteParameters.getPdfSignatureFieldText());

        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setTextParameters(textParameters);

        padesParams.setSignatureFieldId(remoteParameters.getPdfSignatureFieldId());
        padesParams.setSignatureImageParameters(imageParameters);

        return padesParams;
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    public ToBeSignedDTO getDataToSign(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters) {
        LOG.info("GetDataToSign in process...");
        AbstractSignatureParameters parameters = createParameters(remoteParameters);
        eu.europa.esig.dss.signature.DocumentSignatureService service = getServiceForSignature(remoteParameters);
        DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);
        ToBeSigned dataToSign = service.getDataToSign(dssDocument, parameters);
        LOG.info("GetDataToSign is finished");
        return DTOConverter.toToBeSignedDTO(dataToSign);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    public RemoteDocument signDocument(RemoteDocument remoteDocument, ExtendedRemoteSignatureParameters remoteParameters, SignatureValueDTO signatureValueDTO) {
        LOG.info("SignDocument in process...");
        AbstractSignatureParameters parameters = createParameters(remoteParameters);
        eu.europa.esig.dss.signature.DocumentSignatureService service = getServiceForSignature(remoteParameters);
        DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);
        DSSDocument signDocument = (DSSDocument) service.signDocument(dssDocument, parameters, toSignatureValue(signatureValueDTO));
        LOG.info("SignDocument is finished");
        return RemoteDocumentConverter.toRemoteDocument(signDocument);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    public RemoteDocument extendDocument(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters) {
        LOG.info("ExtendDocument in process...");
        AbstractSignatureParameters parameters = createParameters(remoteParameters);
        eu.europa.esig.dss.signature.DocumentSignatureService service = getServiceForSignature(remoteParameters);
        DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);
        DSSDocument extendDocument = (DSSDocument) service.extendDocument(dssDocument, parameters);
        LOG.info("ExtendDocument is finished");
        return RemoteDocumentConverter.toRemoteDocument(extendDocument);
    }

}
