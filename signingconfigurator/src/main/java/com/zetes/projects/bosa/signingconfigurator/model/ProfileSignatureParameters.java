package com.zetes.projects.bosa.signingconfigurator.model;

import eu.europa.esig.dss.enumerations.*;

import javax.persistence.*;
import java.time.Instant;

// parameters which are retrieved from the database based on the profile id
@Entity
@Table
public class ProfileSignatureParameters {

    /**
     * The columns unrelated to signature parameters.
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
     * The columns related to signature parameters.
     */
    @Column
    @Enumerated(EnumType.STRING)
    private ASiCContainerType asicContainerType;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private SignatureLevel signatureLevel;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private SignaturePackaging signaturePackaging;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private SignatureAlgorithm signatureAlgorithm;

    @Column
    @Enumerated(EnumType.STRING)
    private DigestAlgorithm referenceDigestAlgorithm;

    public ProfileSignatureParameters() {
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
     * The columns related to signature parameters.
     */
    public ASiCContainerType getAsicContainerType() {
        return asicContainerType;
    }

    public void setAsicContainerType(ASiCContainerType asicContainerType) {
        this.asicContainerType = asicContainerType;
    }

    public SignatureLevel getSignatureLevel() {
        return signatureLevel;
    }

    public void setSignatureLevel(final SignatureLevel signatureLevel) {
        if (signatureLevel == null) {
            throw new NullPointerException("signatureLevel");
        }
        this.signatureLevel = signatureLevel;
    }

    public DigestAlgorithm getReferenceDigestAlgorithm() {
        return referenceDigestAlgorithm;
    }

    public void setReferenceDigestAlgorithm(DigestAlgorithm referenceDigestAlgorithm) {
        this.referenceDigestAlgorithm = referenceDigestAlgorithm;
    }

    public SignaturePackaging getSignaturePackaging() {
        return signaturePackaging;
    }

    public void setSignaturePackaging(final SignaturePackaging signaturePackaging) {
        this.signaturePackaging = signaturePackaging;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

}
