package com.zetes.projects.bosa.signingconfigurator.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampContainerForm;

import javax.persistence.*;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.time.Instant;

// parameters which are retrieved from the database based on the profile id
@Entity
@Table
public class ProfileTimestampParameters {

    /**
     * The columns unrelated to timestamp parameters.
     */
    @Id
    private String profileId;

    @Column(nullable = false, updatable = false)
    private Instant created;

    @Column(nullable = false)
    private Instant updated;

    @Column(unique = true)
    private Boolean isDefault;

    @Version
    private int version;

    /**
     * The columns related to timestamp parameters.
     */
    @Column
    @Enumerated(EnumType.STRING)
    private DigestAlgorithm digestAlgorithm;

    @Column
    private String canonicalizationMethod;

    @Column
    @Enumerated(EnumType.STRING)
    private TimestampContainerForm containerForm;

    @Column(nullable = false)
    private String tspServer;

    public ProfileTimestampParameters() {
    }

    @PrePersist
    public void generateCreationTimestamp() {
        if (this.created == null) {
            this.created = Instant.now();
        }
        this.updated = this.created;
    }

    /**
     * The columns unrelated to signature parameters.
     */
    public String getProfileId() {
        return profileId;
    }

    public void setProfileId(String profileId) {
        this.profileId = profileId;
    }

    public Instant getCreated() {
        return created;
    }

    public void setCreated(Instant created) {
        this.created = created;
    }

    public Instant getUpdated() {
        return updated;
    }

    public void setUpdated(Instant updated) {
        this.updated = updated;
    }

    public Boolean getIsDefault() {
        return isDefault;
    }

    public void setIsDefault(Boolean isDefault) {
        this.isDefault = isDefault;
    }

    public int getVersion() {
        return version;
    }

    /**
     * The columns related to timestamp parameters.
     */
    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm != null ? digestAlgorithm : DigestAlgorithm.SHA256;
    }

    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public String getCanonicalizationMethod() {
        return canonicalizationMethod != null ? canonicalizationMethod : CanonicalizationMethod.EXCLUSIVE;
    }

    public void setCanonicalizationMethod(String canonicalizationMethod) {
        this.canonicalizationMethod = canonicalizationMethod;
    }

    public TimestampContainerForm getContainerForm() {
        return containerForm;
    }

    public void setContainerForm(TimestampContainerForm containerForm) {
        this.containerForm = containerForm;
    }

    public String getTspServer() {
        return tspServer;
    }

    public void setTspServer(String tspServer) {
        this.tspServer = tspServer;
    }
}
