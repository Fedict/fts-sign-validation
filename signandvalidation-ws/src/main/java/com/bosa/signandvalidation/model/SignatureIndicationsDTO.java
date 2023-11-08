package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class SignatureIndicationsDTO {

    @Schema(description = "The main result of the validation.")
    private Indication indication;

    @Schema(description = "In case the indication is not 'TOTAL_PASSED' the sub indication will contain extra information about the validation issue.")
    private String subIndicationLabel;

    @Schema(description = "A validation report in XML form")
    private String report;

    @Schema(description = "A simple validation report. <BR>It is the same validation result as the 'SignBox' validation output")
    private NormalizedReport normalizedReport;

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
}
