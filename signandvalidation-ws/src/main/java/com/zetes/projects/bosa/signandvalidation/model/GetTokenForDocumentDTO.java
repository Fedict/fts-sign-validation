/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zetes.projects.bosa.signandvalidation.model;

/**
 *
 * @author wouter
 */
public class GetTokenForDocumentDTO {
    private String name;
    private String pwd;
    private String in;
    private String out;
    private String prof;
    private String xslt;

    public GetTokenForDocumentDTO() {
    }
    public GetTokenForDocumentDTO(String name, String pwd, String in, String out, String prof, String xslt) {
        this.name = name;
        this.pwd = pwd;
        this.in = in;
        this.out = out;
        this.prof = prof;
        this.xslt = xslt;
    }
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getPwd() {
        return pwd;
    }
    public void setPwd(String pwd) {
        this.pwd = pwd;
    }
    public String getIn() {
        return in;
    }
    public void setIn(String in) {
        this.in = in;
    }
    public String getOut() {
        return out;
    }
    public void setOut(String out) {
        this.out = out;
    }
    public String getProf() {
        return prof;
    }
    public void setProf(String prof) {
        this.prof = prof;
    }
    public String getXslt() {
        return xslt;
    }
    public void setXslt(String xslt) {
        this.xslt = xslt;
    }
}
