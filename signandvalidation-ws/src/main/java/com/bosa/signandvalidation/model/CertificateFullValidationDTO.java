package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateFullValidationDTO {

    @Schema(description = "The information set that was used as part of the validation process")
    private XmlDiagnosticData diagnosticData;

    @Schema(description = "A 'general summary' validation report")
    private XmlSimpleCertificateReport simpleCertificateReport;

    @Schema(description = "A validation report with the full validation information")
    private XmlDetailedReport detailedReport;
}
