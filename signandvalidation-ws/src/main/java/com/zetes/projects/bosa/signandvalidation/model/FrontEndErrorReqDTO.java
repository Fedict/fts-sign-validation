package com.zetes.projects.bosa.signandvalidation.model;

public class FrontEndErrorReqDTO {

    private String err;
    private String report;
    private String result;
    private String token;

    public FrontEndErrorReqDTO() {
    }

    public FrontEndErrorReqDTO(String err, String report, String result, String token) {
        this.err = err;
        this.report = report;
        this.result = result;
        this.token = token;
    }

    public String getErr() {
        return err;
    }

    public String getReport() {
        return report;
    }

    public String getResult() {
        return result;
    }

    public String getToken() {
        return token;
    }
}
