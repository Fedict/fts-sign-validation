package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;

public class ReportDTO {

    private XmlSimpleReport simpleReport;
    private XmlDetailedReport detailedReport;
    private byte[] signingCertificate;

    public ReportDTO(XmlSimpleReport simpleReport, XmlDetailedReport detailedReport, byte[] signingCertificate) {
        this.simpleReport = simpleReport;
        this.detailedReport = detailedReport;
        this.signingCertificate = signingCertificate;
    }

    public XmlSimpleReport getXmlSimpleReport() {
        return simpleReport;
    }

    public XmlDetailedReport getXmlDetailedReport() {
        return detailedReport;
    }

    public byte[] getSigningCertificate() {
        return signingCertificate;
    }
}
