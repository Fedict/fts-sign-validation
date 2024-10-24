package com.bosa.signingconfigurator.model;

import com.bosa.signandvalidation.model.SigningType;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.ArrayList;
import java.util.List;

// parameters which are retrieved from the database based on the profile id
@Getter
@Setter
@NoArgsConstructor
public class ProfileSignatureParameters extends JsonObject {

    /**
     * The columns unrelated to signature parameters.
     */
    private String profileId;

    private Boolean isDefault;

    /**
     * The columns related to signature parameters.
     */
    private ASiCContainerType asicContainerType;

    private SignatureLevel signatureLevel;

    private JWSSerializationType jadesSerializationType;

    private SignaturePackaging signaturePackaging;

    private DigestAlgorithm digestAlgorithm;

    private MaskGenerationFunction maskGenerationFunction;

    private DigestAlgorithm referenceDigestAlgorithm;

    /**
     * Overridable default parameters
     */
    private Boolean trustAnchorBPPolicy;

    private Boolean addCertPathToKeyinfo;

    private String policyId;

    private ObjectIdentifierQualifier policyQualifier;

    private String policyDescription;

    private DigestAlgorithm policyDigestAlgorithm;

    private byte[] policyDigestValue;

    private String policySpuri;

    private List<CommitmentTypeEnum> commitmentTypeIndications = new ArrayList<>();

    private Boolean signWithExpiredCertificate;

    private Boolean generateTBSWithoutCertificate;

    private DigestAlgorithm contentTimestampDigestAlgorithm;

    private String contentTimestampCanonicalizationMethod;

    private TimestampContainerForm contentTimestampContainerForm;

    private DigestAlgorithm signatureTimestampDigestAlgorithm;

    private String signatureTimestampCanonicalizationMethod;

    private TimestampContainerForm signatureTimestampContainerForm;

    private DigestAlgorithm archiveTimestampDigestAlgorithm;

    private String archiveTimestampCanonicalizationMethod;

    private TimestampContainerForm archiveTimestampContainerForm;

    private String tspServer;

    private Boolean devOnlyProfile;

    private Boolean embedXML;

    private RevocationStrategy revocationStrategy;

    private SigningType signingType;

    private SignatureForm signatureForm;

    private Boolean returnDigest;

    private String validationPolicyFilename;

    private String extraTrustFilename;

    /*
     * The values unrelated to signature parameters.
     */

    @Override
    public Boolean getIsDefault() {
        return isDefault != null && isDefault;
    }

    /*
     * The values related to signature parameters.
     */
    public void setSignatureLevel(final SignatureLevel signatureLevel) {
        if (signatureLevel == null) {
            throw new NullPointerException("signatureLevel");
        }
        this.signatureLevel = signatureLevel;
    }

    public void setJadesSerializationType(final JWSSerializationType jadesSerializationType) {
        if (jadesSerializationType == null) {
            throw new NullPointerException("jadesSerializationType");
        }
        this.jadesSerializationType = jadesSerializationType;
    }

    public Boolean getTrustAnchorBPPolicy() {
        return trustAnchorBPPolicy != null ? trustAnchorBPPolicy : true;
    }

    public Boolean getAddCertPathToKeyinfo() {
        return addCertPathToKeyinfo != null ? addCertPathToKeyinfo : false;
    }

    public Boolean getSignWithExpiredCertificate() {
        return signWithExpiredCertificate != null ? signWithExpiredCertificate : false;
    }

    public Boolean getGenerateTBSWithoutCertificate() {
        return generateTBSWithoutCertificate != null ? generateTBSWithoutCertificate : false;
    }

    public DigestAlgorithm getContentTimestampDigestAlgorithm() {
        return contentTimestampDigestAlgorithm != null ? contentTimestampDigestAlgorithm : DigestAlgorithm.SHA256;
    }

    public String getContentTimestampCanonicalizationMethod() {
        return contentTimestampCanonicalizationMethod != null ? contentTimestampCanonicalizationMethod : CanonicalizationMethod.EXCLUSIVE;
    }

    // combine ContentTimestampParameters
    public RemoteTimestampParameters getContentTimestampParameters() {
        return new RemoteTimestampParameters(getContentTimestampContainerForm(), getContentTimestampDigestAlgorithm(), getContentTimestampCanonicalizationMethod());
    }

    public DigestAlgorithm getSignatureTimestampDigestAlgorithm() {
        return signatureTimestampDigestAlgorithm != null ? signatureTimestampDigestAlgorithm : DigestAlgorithm.SHA256;
    }

    public String getSignatureTimestampCanonicalizationMethod() {
        return signatureTimestampCanonicalizationMethod != null ? signatureTimestampCanonicalizationMethod : CanonicalizationMethod.EXCLUSIVE;
    }

    // combine SignatureTimestampParameters
    public RemoteTimestampParameters getSignatureTimestampParameters() {
        return new RemoteTimestampParameters(getSignatureTimestampContainerForm(), getSignatureTimestampDigestAlgorithm(), getSignatureTimestampCanonicalizationMethod());
    }

    public DigestAlgorithm getArchiveTimestampDigestAlgorithm() {
        return archiveTimestampDigestAlgorithm != null ? archiveTimestampDigestAlgorithm : DigestAlgorithm.SHA256;
    }

    public String getArchiveTimestampCanonicalizationMethod() {
        return archiveTimestampCanonicalizationMethod != null ? archiveTimestampCanonicalizationMethod : CanonicalizationMethod.EXCLUSIVE;
    }
    // combine ArchiveTimestampParameters
    public RemoteTimestampParameters getArchiveTimestampParameters() {
        return new RemoteTimestampParameters(getArchiveTimestampContainerForm(), getArchiveTimestampDigestAlgorithm(), getArchiveTimestampCanonicalizationMethod());
    }

    @Override
    public Boolean getDevOnlyProfile() {
        return devOnlyProfile != null && devOnlyProfile;
    }

    public Boolean getEmbedXML() {
        return embedXML != null && embedXML;
    }

    public RevocationStrategy getRevocationStrategy() { return revocationStrategy == null ? RevocationStrategy.DEFAULT : revocationStrategy; }

    public SignatureForm getSignatureForm() { return signatureForm == null ? SignatureForm.PAdES : signatureForm; }

    public SigningType getSigningType() { return signingType == null ? SigningType.Standard : signingType; }

    public Boolean isReturnDigest() { return returnDigest == null || returnDigest; }

    public String getValidationPolicyFilename() { return validationPolicyFilename; }

    public String getExtraTrustFilename() { return extraTrustFilename; }
}
