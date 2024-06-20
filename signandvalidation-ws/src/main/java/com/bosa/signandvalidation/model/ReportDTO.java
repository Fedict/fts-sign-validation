package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import lombok.Data;

@Data
public class ReportDTO {
    private final XmlSimpleReport simpleReport;
    private final XmlDetailedReport detailedReport;
    private final byte[] signingCertificate;
    private final NormalizedReport normalizedReport;
}
