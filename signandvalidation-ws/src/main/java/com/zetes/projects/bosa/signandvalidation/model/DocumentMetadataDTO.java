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
    private boolean readPhoto;
    private boolean disallowSignedDownloads;
    private boolean requestDocumentReadConfirm;
    
    public DocumentMetadataDTO(String filename, String mimetype, String xsltUrl, boolean readPhoto, boolean disallowSignedDownloads, boolean requestDocumentReadConfirm) {
        this.filename = filename;
        this.mimetype = mimetype;
        this.xsltUrl = xsltUrl;
        this.readPhoto = readPhoto;
        this.disallowSignedDownloads = disallowSignedDownloads;
        this.requestDocumentReadConfirm = requestDocumentReadConfirm;
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
    public boolean getReadPhoto() {
        return readPhoto;
    }
    public void setReadPhoto(boolean readPhoto) {
        this.readPhoto = readPhoto;
    }
    public boolean getDisallowSignedDownloads() {
        return disallowSignedDownloads;
    }
    public void setDisallowSignedDownloads(boolean disallowSignedDownloads) {
        this.disallowSignedDownloads = disallowSignedDownloads;
    }
    public boolean getRequestDocumentReadConfirm() {
        return requestDocumentReadConfirm;
    }
    public void setRequestDocumentReadConfirm(boolean requestDocumentReadConfirm) {
        this.requestDocumentReadConfirm = requestDocumentReadConfirm;
    }
}
