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
public class DocumentMetadataDTO {
    private String filename;
    private String mimetype;
    private String xsltUrl;
    
    public DocumentMetadataDTO(String filename, String mimetype, String xsltUrl) {
        this.filename = filename;
        this.mimetype = mimetype;
        this.xsltUrl = xsltUrl;
    }
    public String getFilename() {
        return filename;
    }
    public void setFilename(String filename) {
        this.filename = filename;
    }
    public String getMimetype() {
        return mimetype;
    }
    public void setMimetype(String mimetype) {
        this.mimetype = mimetype;
    }
    public String getXsltUrl() {
        return xsltUrl;
    }
    public void setXsltUrl(String xsltUrl) {
        this.xsltUrl = xsltUrl;
    }
}
