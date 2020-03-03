package com.zetes.projects.bosa.signandvalidation.model;

import java.util.List;

public class IndicationsListDTO {

    private List<IndicationsDTO> indications;

    public IndicationsListDTO() {
    }

    public IndicationsListDTO(List<IndicationsDTO> indications) {
        this.indications = indications;
    }

    public List<IndicationsDTO> getIndications() {
        return indications;
    }

    public void setIndications(List<IndicationsDTO> indications) {
        this.indications = indications;
    }

}
