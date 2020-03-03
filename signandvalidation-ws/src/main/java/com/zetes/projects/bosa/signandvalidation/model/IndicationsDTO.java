package com.zetes.projects.bosa.signandvalidation.model;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;

public class IndicationsDTO {

    private Indication indication;

    private SubIndication subIndication;

    public IndicationsDTO() {
    }

    public IndicationsDTO(Indication indication) {
        this.indication = indication;
    }

    public IndicationsDTO(Indication indication, SubIndication subIndication) {
        this.indication = indication;
        this.subIndication = subIndication;
    }

    public Indication getIndication() {
        return indication;
    }

    public void setIndication(Indication indication) {
        this.indication = indication;
    }

    public SubIndication getSubIndication() {
        return subIndication;
    }

    public void setSubIndication(SubIndication subIndication) {
        this.subIndication = subIndication;
    }
}
