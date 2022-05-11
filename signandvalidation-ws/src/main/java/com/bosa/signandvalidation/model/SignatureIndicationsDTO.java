package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;

public class SignatureIndicationsDTO {

    private Indication indication;

    private String subIndicationLabel;

    private XmlDiagnosticData diagnosticData;

    private XmlDetailedReport report;

    public SignatureIndicationsDTO() {
    }

    public SignatureIndicationsDTO(Indication indication) {
        this.indication = indication;
    }

    public SignatureIndicationsDTO(Indication indication, SubIndication subIndication) {
        this.indication = indication;
        this.subIndicationLabel = subIndication == null ? "" : subIndication.toString();
    }

    public SignatureIndicationsDTO(Indication indication, String subIndication) {
        this.indication = indication;
        this.subIndicationLabel = subIndication;
    }

    public Indication getIndication() {
        return indication;
    }

    public void setIndication(Indication indication) {
        this.indication = indication;
    }

    public String getSubIndicationLabel() {
        return subIndicationLabel;
    }

    public void setSubIndicationLabel(String subIndicationLabel) {
        this.subIndicationLabel = subIndicationLabel;
    }

    public void setReport(XmlDetailedReport report) { this.report = report; }

    public XmlDetailedReport getReport() { return this.report; }

    public void setDiagnosticData(XmlDiagnosticData diagnosticData) { this.diagnosticData = diagnosticData; }

    public XmlDiagnosticData getDiagnosticData() { return this.diagnosticData; }
}
