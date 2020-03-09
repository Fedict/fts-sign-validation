package com.zetes.projects.bosa.resourcelocator.model;

import java.util.List;

public class SigningTypeListDTO {

    private List<SigningTypeDTO> signingTypes;

    public SigningTypeListDTO() {
    }

    public SigningTypeListDTO(List<SigningTypeDTO> signingTypes) {
        this.signingTypes = signingTypes;
    }

    public List<SigningTypeDTO> getSigningTypes() {
        return signingTypes;
    }

    public void setSigningTypes(List<SigningTypeDTO> signingTypes) {
        this.signingTypes = signingTypes;
    }

}
