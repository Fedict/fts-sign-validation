package com.zetes.projects.bosa.signandvalidation.model;

import java.util.List;

public class IndicationsListDTO {

    private List<CertificateIndicationsDTO> indications;

    public IndicationsListDTO() {
    }

    public IndicationsListDTO(List<CertificateIndicationsDTO> indications) {
        this.indications = indications;
    }

    public List<CertificateIndicationsDTO> getIndications() {
        return indications;
    }

    public void setIndications(List<CertificateIndicationsDTO> indications) {
        this.indications = indications;
    }

}
