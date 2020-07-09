package com.zetes.projects.bosa.signandvalidation.model;

import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.List;

public class TimestampDocumentMultipleDTO {

    private List<RemoteDocument> documents;
    private String profileId;

    public TimestampDocumentMultipleDTO() {
    }

    public TimestampDocumentMultipleDTO(List<RemoteDocument> documents, String profileId) {
        this.documents = documents;
        this.profileId = profileId;
    }

    public List<RemoteDocument> getDocuments() {
        return documents;
    }

    public void setDocuments(List<RemoteDocument> documents) {
        this.documents = documents;
    }

    public String getProfileId() {
        return profileId;
    }

    public void setProfileId(String profileId) {
        this.profileId = profileId;
    }
}
