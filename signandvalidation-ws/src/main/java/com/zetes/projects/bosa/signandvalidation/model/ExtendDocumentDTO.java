package com.zetes.projects.bosa.signandvalidation.model;

import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.List;

public class ExtendDocumentDTO {

    private RemoteDocument toExtendDocument;
    private String extendProfileId;
    private List<RemoteDocument> detachedContents;

    public ExtendDocumentDTO() {
    }

    public ExtendDocumentDTO(RemoteDocument toExtendDocument, String extendProfileId, List<RemoteDocument> detachedContents) {
        this.toExtendDocument = toExtendDocument;
        this.extendProfileId = extendProfileId;
        this.detachedContents = detachedContents;
    }

    public RemoteDocument getToExtendDocument() {
        return toExtendDocument;
    }

    public void setToExtendDocument(RemoteDocument toExtendDocument) {
        this.toExtendDocument = toExtendDocument;
    }

    public String getExtendProfileId() {
        return extendProfileId;
    }

    public void setExtendProfileId(String extendProfileId) {
        this.extendProfileId = extendProfileId;
    }

    public List<RemoteDocument> getDetachedContents() {
        return detachedContents;
    }

    public void setDetachedContents(List<RemoteDocument> detachedContents) {
        this.detachedContents = detachedContents;
    }

}
