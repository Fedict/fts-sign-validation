package com.zetes.projects.bosa.signingconfigurator.model;

import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;

import javax.persistence.*;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static javax.persistence.FetchType.EAGER;

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
    private DigestAlgorithm digestAlgorithm;

    @Enumerated(EnumType.STRING)
    private MaskGenerationFunction maskGenerationFunction;

    @Column
    @Enumerated(EnumType.STRING)
    private DigestAlgorithm referenceDigestAlgorithm;

    /**
     * Overridable default parameters
     */
    @Column
    private Boolean trustAnchorBPPolicy;

    @Column
    private String policyId;

    @Column
    private String policyQualifier;

    @Column
    private String policyDescription;

    @Column
    @Enumerated(EnumType.STRING)
    private DigestAlgorithm policyDigestAlgorithm;

    @Column
    private byte[] policyDigestValue;

    @Column
    private String policySpuri;

    @ElementCollection(fetch = EAGER)
    private List<String> commitmentTypeIndications = new ArrayList<>();

    @Column
    private Boolean signWithExpiredCertificate;

    @Column
    private Boolean generateTBSWithoutCertificate;

    @Column
    @Enumerated(EnumType.STRING)
    private DigestAlgorithm contentTimestampDigestAlgorithm;

    @Column
    private String contentTimestampCanonicalizationMethod;

    @Column
    @Enumerated(EnumType.STRING)
    private TimestampContainerForm contentTimestampContainerForm;

    @Column
    @Enumerated(EnumType.STRING)
    private DigestAlgorithm signatureTimestampDigestAlgorithm;

    @Column
    private String signatureTimestampCanonicalizationMethod;

    @Column
    @Enumerated(EnumType.STRING)
    private TimestampContainerForm signatureTimestampContainerForm;

    @Column
    @Enumerated(EnumType.STRING)
    private DigestAlgorithm archiveTimestampDigestAlgorithm;

    @Column
    private String archiveTimestampCanonicalizationMethod;

    @Column
    @Enumerated(EnumType.STRING)
    private TimestampContainerForm archiveTimestampContainerForm;

    @Column(nullable = false)
    private String tspServer;

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

    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public MaskGenerationFunction getMaskGenerationFunction() {
        return maskGenerationFunction;
    }

    public void setMaskGenerationFunction(MaskGenerationFunction maskGenerationFunction) {
        this.maskGenerationFunction = maskGenerationFunction;
    }

    public Boolean getTrustAnchorBPPolicy() {
        return trustAnchorBPPolicy != null ? trustAnchorBPPolicy : true;
    }

    public void setTrustAnchorBPPolicy(Boolean trustAnchorBPPolicy) {
        this.trustAnchorBPPolicy = trustAnchorBPPolicy;
    }

    public String getPolicyId() {
        return policyId;
    }

    public void setPolicyId(String policyId) {
        this.policyId = policyId;
    }

    public String getPolicyQualifier() {
        return policyQualifier;
    }

    public void setPolicyQualifier(String policyQualifier) {
        this.policyQualifier = policyQualifier;
    }

    public String getPolicyDescription() {
        return policyDescription;
    }

    public void setPolicyDescription(String policyDescription) {
        this.policyDescription = policyDescription;
    }

    public DigestAlgorithm getPolicyDigestAlgorithm() {
        return policyDigestAlgorithm;
    }

    public void setPolicyDigestAlgorithm(DigestAlgorithm policyDigestAlgorithm) {
        this.policyDigestAlgorithm = policyDigestAlgorithm;
    }

    public byte[] getPolicyDigestValue() {
        return policyDigestValue;
    }

    public void setPolicyDigestValue(byte[] policyDigestValue) {
        this.policyDigestValue = policyDigestValue;
    }

    public String getPolicySpuri() {
        return policySpuri;
    }

    public void setPolicySpuri(String policySpuri) {
        this.policySpuri = policySpuri;
    }

    public List<String> getCommitmentTypeIndications() {
        return commitmentTypeIndications;
    }

    public void setCommitmentTypeIndications(List<String> commitmentTypeIndications) {
        this.commitmentTypeIndications = commitmentTypeIndications;
    }

    public Boolean getSignWithExpiredCertificate() {
        return signWithExpiredCertificate != null ? signWithExpiredCertificate : false;
    }

    public void setSignWithExpiredCertificate(Boolean signWithExpiredCertificate) {
        this.signWithExpiredCertificate = signWithExpiredCertificate;
    }

    public Boolean getGenerateTBSWithoutCertificate() {
        return generateTBSWithoutCertificate != null ? generateTBSWithoutCertificate : false;
    }

    public void setGenerateTBSWithoutCertificate(Boolean generateTBSWithoutCertificate) {
        this.generateTBSWithoutCertificate = generateTBSWithoutCertificate;
    }

    public DigestAlgorithm getContentTimestampDigestAlgorithm() {
        return contentTimestampDigestAlgorithm != null ? contentTimestampDigestAlgorithm : DigestAlgorithm.SHA256;
    }

    public void setContentTimestampDigestAlgorithm(DigestAlgorithm contentTimestampDigestAlgorithm) {
        this.contentTimestampDigestAlgorithm = contentTimestampDigestAlgorithm;
    }

    public String getContentTimestampCanonicalizationMethod() {
        return contentTimestampCanonicalizationMethod != null ? contentTimestampCanonicalizationMethod : CanonicalizationMethod.EXCLUSIVE;
    }

    public void setContentTimestampCanonicalizationMethod(String contentTimestampCanonicalizationMethod) {
        this.contentTimestampCanonicalizationMethod = contentTimestampCanonicalizationMethod;
    }

    public TimestampContainerForm getContentTimestampContainerForm() {
        return contentTimestampContainerForm;
    }

    public void setContentTimestampContainerForm(TimestampContainerForm contentTimestampContainerForm) {
        this.contentTimestampContainerForm = contentTimestampContainerForm;
    }

    // combine ContentTimestampParameters
    public RemoteTimestampParameters getContentTimestampParameters() {
        return new RemoteTimestampParameters(getContentTimestampContainerForm(), getContentTimestampDigestAlgorithm(), getContentTimestampCanonicalizationMethod());
    }

    public DigestAlgorithm getSignatureTimestampDigestAlgorithm() {
        return signatureTimestampDigestAlgorithm != null ? signatureTimestampDigestAlgorithm : DigestAlgorithm.SHA256;
    }

    public void setSignatureTimestampDigestAlgorithm(DigestAlgorithm signatureTimestampDigestAlgorithm) {
        this.signatureTimestampDigestAlgorithm = signatureTimestampDigestAlgorithm;
    }

    public String getSignatureTimestampCanonicalizationMethod() {
        return signatureTimestampCanonicalizationMethod != null ? signatureTimestampCanonicalizationMethod : CanonicalizationMethod.EXCLUSIVE;
    }

    public void setSignatureTimestampCanonicalizationMethod(String signatureTimestampCanonicalizationMethod) {
        this.signatureTimestampCanonicalizationMethod = signatureTimestampCanonicalizationMethod;
    }

    public TimestampContainerForm getSignatureTimestampContainerForm() {
        return signatureTimestampContainerForm;
    }

    public void setSignatureTimestampContainerForm(TimestampContainerForm signatureTimestampContainerForm) {
        this.signatureTimestampContainerForm = signatureTimestampContainerForm;
    }

    // combine SignatureTimestampParameters
    public RemoteTimestampParameters getSignatureTimestampParameters() {
        return new RemoteTimestampParameters(getSignatureTimestampContainerForm(), getSignatureTimestampDigestAlgorithm(), getSignatureTimestampCanonicalizationMethod());
    }

    public DigestAlgorithm getArchiveTimestampDigestAlgorithm() {
        return archiveTimestampDigestAlgorithm != null ? archiveTimestampDigestAlgorithm : DigestAlgorithm.SHA256;
    }

    public void setArchiveTimestampDigestAlgorithm(DigestAlgorithm archiveTimestampDigestAlgorithm) {
        this.archiveTimestampDigestAlgorithm = archiveTimestampDigestAlgorithm;
    }

    public String getArchiveTimestampCanonicalizationMethod() {
        return archiveTimestampCanonicalizationMethod != null ? archiveTimestampCanonicalizationMethod : CanonicalizationMethod.EXCLUSIVE;
    }

    public void setArchiveTimestampCanonicalizationMethod(String archiveTimestampCanonicalizationMethod) {
        this.archiveTimestampCanonicalizationMethod = archiveTimestampCanonicalizationMethod;
    }

    public TimestampContainerForm getArchiveTimestampContainerForm() {
        return archiveTimestampContainerForm;
    }

    public void setArchiveTimestampContainerForm(TimestampContainerForm archiveTimestampContainerForm) {
        this.archiveTimestampContainerForm = archiveTimestampContainerForm;
    }

    // combine ArchiveTimestampParameters
    public RemoteTimestampParameters getArchiveTimestampParameters() {
        return new RemoteTimestampParameters(getArchiveTimestampContainerForm(), getArchiveTimestampDigestAlgorithm(), getArchiveTimestampCanonicalizationMethod());
    }

    public String getTspServer() {
        return tspServer;
    }

    public void setTspServer(String tspServer) {
        this.tspServer = tspServer;
    }
}
