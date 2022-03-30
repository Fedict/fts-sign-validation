package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.ws.dto.RemoteDocument;

public class TimestampDocumentDTO {

    private RemoteDocument document;
    private String profileId;

    public TimestampDocumentDTO() {
    }

    public TimestampDocumentDTO(RemoteDocument document, String profileId) {
        this.document = document;
        this.profileId = profileId;
    }

    public RemoteDocument getDocument() {
        return document;
    }

    public void setDocument(RemoteDocument document) {
        this.document = document;
    }

    public String getProfileId() {
        return profileId;
    }

    public void setProfileId(String profileId) {
        this.profileId = profileId;
    }
}
