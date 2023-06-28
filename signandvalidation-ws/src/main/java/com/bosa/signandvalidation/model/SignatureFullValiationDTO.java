package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignatureFullValiationDTO {
    @Schema(name = "diagnosticData", required = true, description = "The information set that was used as part of the validation process")
    private XmlDiagnosticData diagnosticData;
    @Schema(name = "simpleReport", required = false, description = "A 'general summary' validation report")
    private XmlSimpleReport simpleReport;
    @Schema(name = "detailedReport", required = true, description = "A validation report with the full validation information")
    private XmlDetailedReport detailedReport;
}
