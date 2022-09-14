package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ValidateFullReportDTO {
    private SimpleReport simpleReport;
    private XmlDetailedReport detailedReport;
    private XmlDiagnosticData diagnosticData;
    private ValidationReportType validationReport;
}
