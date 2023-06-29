package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateIndicationsDTO {

    @Schema(description = "The 'common name' of the certificate")
    private String commonName;

    @Schema(description = "The main result of the validation.")
    private Indication indication;

    @Schema(description = "In case the indication is not 'TOTAL_PASSED' the sub indication will contain extra information about the validation issue.")
    private SubIndication subIndication;

    @Schema(description = "True if the validated certificate can sign the 'expectedKeyUsage' signature type")
    private boolean keyUsageCheckOk;

    public CertificateIndicationsDTO(String commonName, Indication indication, boolean keyUsageCheckOk) {
        this.commonName = commonName;
        this.indication = indication;
        this.keyUsageCheckOk = keyUsageCheckOk;
    }
}
