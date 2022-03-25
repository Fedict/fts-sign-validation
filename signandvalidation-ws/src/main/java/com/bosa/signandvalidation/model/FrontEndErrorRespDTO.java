package com.bosa.signandvalidation.model;

public class FrontEndErrorRespDTO {

    private String ref;

    public FrontEndErrorRespDTO() {
    }

    public FrontEndErrorRespDTO(String ref) {
        this.ref = ref;
    }

    public void setRef(String ref) {
        this.ref = ref;
    }

    public String getRef() {
        return ref;
    }
}
