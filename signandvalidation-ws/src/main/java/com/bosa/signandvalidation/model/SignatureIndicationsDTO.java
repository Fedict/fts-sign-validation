package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import lombok.Data;

@Data
public class SignatureIndicationsDTO {

    private Indication indication;

    private String subIndicationLabel;

    private XmlDiagnosticData diagnosticData;

    private String report;

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
