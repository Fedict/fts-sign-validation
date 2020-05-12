package com.zetes.projects.bosa.signingconfigurator.model;

import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

public class ExtendedRemoteSignatureParameters extends RemoteSignatureParameters {

    private String pdfSignatureFieldId;
    private String pdfSignatureFieldText;

    public ExtendedRemoteSignatureParameters() {
    }

    public String getPdfSignatureFieldId() {
        return pdfSignatureFieldId;
    }

    public void setPdfSignatureFieldId(String pdfSignatureFieldId) {
        this.pdfSignatureFieldId = pdfSignatureFieldId;
    }

    public String getPdfSignatureFieldText() {
        return pdfSignatureFieldText;
    }

    public void setPdfSignatureFieldText(String pdfSignatureFieldText) {
        this.pdfSignatureFieldText = pdfSignatureFieldText;
    }

}
