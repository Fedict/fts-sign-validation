package com.bosa.signingconfigurator.service;


import com.bosa.signingconfigurator.dao.ProfileSignatureParametersDao;
import com.bosa.signingconfigurator.dao.ProfileTimestampParametersDao;
import com.bosa.signingconfigurator.exception.NullParameterException;
import com.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.bosa.signingconfigurator.model.PolicyParameters;
import com.bosa.signingconfigurator.model.ProfileSignatureParameters;
import com.bosa.signingconfigurator.model.ProfileTimestampParameters;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteBLevelParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.List;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;

@Service
public class SigningConfiguratorService {

    @Autowired
    ProfileSignatureParametersDao signatureDao;

    @Autowired
    ProfileTimestampParametersDao timestampDao;

    @Autowired
    OnlineTSPSource tspSource;

    @Autowired
    FileCacheDataLoader fileCacheDataLoader;

    public RemoteSignatureParameters getSignatureParams(ProfileSignatureParameters signProfile, ClientSignatureParameters clientParams, PolicyParameters policyParameters) throws ProfileNotFoundException, NullParameterException, IOException {
        if (clientParams == null || clientParams.getSigningCertificate() == null || clientParams.getSigningDate() == null) {
            throw new NullParameterException("Parameters should not be null");
        }

        if (signProfile == null) signProfile = findDefaultProfileParams();

            // check to add policy (EPES)
        if (policyParameters != null && policyParameters.isPolicyValid()) {
            byte[] digestedBytes = calcPolicyDigest(policyParameters.getPolicyId(), policyParameters.getPolicyDigestAlgorithm());
            // Fill policy entries
            signProfile.setPolicyId(policyParameters.getPolicyId());
            signProfile.setPolicySpuri(policyParameters.getPolicyId());
            if(policyParameters.getPolicyDescription()!=null)
            {
                signProfile.setPolicyDescription(policyParameters.getPolicyDescription());
            }
            signProfile.setPolicyQualifier(ObjectIdentifierQualifier.OID_AS_URI);
            signProfile.setPolicyDigestAlgorithm(policyParameters.getPolicyDigestAlgorithm());
            signProfile.setPolicyDigestValue(digestedBytes);
        }
        tspSource.setTspServer(signProfile.getTspServer());
        return fillRemoteSignatureParams(clientParams, signProfile);
    }

    // calculate policy file digest
    private byte[] calcPolicyDigest(String policyId, DigestAlgorithm policyDigestAlgorithm) throws IOException {

        DSSDocument doc = fileCacheDataLoader.getDocument(policyId);
        // Java 9
        // byte[] bytes = doc.openStream().readAllBytes();
        // Java 8
        InputStream is = doc.openStream();
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[4096];
        while ((nRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        buffer.flush();
        byte[] bytes = buffer.toByteArray();

        DSSDocument policyContent = new InMemoryDocument(bytes);
        return DSSUtils.digest(policyDigestAlgorithm, policyContent);
    }

    public RemoteSignatureParameters getExtensionParams(ProfileSignatureParameters profile, List<RemoteDocument> detachedContents) throws ProfileNotFoundException {
        if (profile == null) profile = findDefaultProfileParams();
        tspSource.setTspServer(profile.getTspServer());
        return fillExtensionParams(detachedContents, profile);
    }

    public RemoteTimestampParameters getTimestampParams(String profileId) throws ProfileNotFoundException {
        ProfileTimestampParameters profileParams;
        if (profileId == null) {
            profileParams = findDefaultTimestampProfileParams();
        } else {
            profileParams = findTimestampProfileParamsById(profileId);
        }

        tspSource.setTspServer(profileParams.getTspServer());
        return new RemoteTimestampParameters(profileParams.getContainerForm(), profileParams.getDigestAlgorithm(), profileParams.getCanonicalizationMethod());
    }

    private RemoteSignatureParameters fillRemoteSignatureParams(ClientSignatureParameters clientParams, ProfileSignatureParameters profileParams) {
        RemoteSignatureParameters remoteSignatureParams = new RemoteSignatureParameters();
        RemoteBLevelParameters remoteBLevelParams = new RemoteBLevelParameters();

        fillDefaultParams(profileParams, remoteSignatureParams, remoteBLevelParams);
        fillProfileParams(profileParams, remoteSignatureParams);
        fillClientParams(clientParams, remoteSignatureParams, remoteBLevelParams);

        remoteSignatureParams.setBLevelParams(remoteBLevelParams);

        return remoteSignatureParams;
    }

    private RemoteSignatureParameters fillExtensionParams(List<RemoteDocument> detachedContents, ProfileSignatureParameters profileParams) {
        RemoteSignatureParameters remoteSignatureParams = new RemoteSignatureParameters();
        RemoteBLevelParameters remoteBLevelParams = new RemoteBLevelParameters();

        fillDefaultParams(profileParams, remoteSignatureParams, remoteBLevelParams);
        fillProfileParams(profileParams, remoteSignatureParams);
        remoteSignatureParams.setDetachedContents(detachedContents);

        remoteSignatureParams.setBLevelParams(remoteBLevelParams);

        return remoteSignatureParams;
    }

    private void fillDefaultParams(ProfileSignatureParameters profileParams, RemoteSignatureParameters remoteSignatureParams, RemoteBLevelParameters remoteBLevelParams) {
        remoteSignatureParams.setContentTimestampParameters(profileParams.getContentTimestampParameters());
        remoteSignatureParams.setSignatureTimestampParameters(profileParams.getSignatureTimestampParameters());
        remoteSignatureParams.setArchiveTimestampParameters(profileParams.getArchiveTimestampParameters());
        remoteSignatureParams.setSignWithExpiredCertificate(profileParams.getSignWithExpiredCertificate());
        remoteSignatureParams.setGenerateTBSWithoutCertificate(profileParams.getGenerateTBSWithoutCertificate());
        remoteSignatureParams.setEmbedXML(profileParams.getEmbedXML());

        remoteBLevelParams.setTrustAnchorBPPolicy(profileParams.getTrustAnchorBPPolicy());
        remoteBLevelParams.setPolicyId(profileParams.getPolicyId());
        remoteBLevelParams.setPolicyQualifier(profileParams.getPolicyQualifier());
        remoteBLevelParams.setPolicyDescription(profileParams.getPolicyDescription());
        remoteBLevelParams.setPolicyDigestAlgorithm(profileParams.getPolicyDigestAlgorithm());
        remoteBLevelParams.setPolicyDigestValue(profileParams.getPolicyDigestValue());
        remoteBLevelParams.setPolicySpuri(profileParams.getPolicySpuri());
        remoteBLevelParams.setCommitmentTypeIndications(profileParams.getCommitmentTypeIndications());
    }

    private void fillProfileParams(ProfileSignatureParameters profileParams, RemoteSignatureParameters remoteSignatureParams) {
        remoteSignatureParams.setAsicContainerType(profileParams.getAsicContainerType());
        remoteSignatureParams.setSignatureLevel(profileParams.getSignatureLevel());
        remoteSignatureParams.setJwsSerializationType(profileParams.getJadesSerializationType());
        remoteSignatureParams.setSignaturePackaging(profileParams.getSignaturePackaging());
        remoteSignatureParams.setDigestAlgorithm(profileParams.getDigestAlgorithm());
        remoteSignatureParams.setMaskGenerationFunction(profileParams.getMaskGenerationFunction());
        remoteSignatureParams.setReferenceDigestAlgorithm(profileParams.getReferenceDigestAlgorithm());
    }

    private void fillClientParams(ClientSignatureParameters clientParams, RemoteSignatureParameters remoteSignatureParams, RemoteBLevelParameters remoteBLevelParams) {
        remoteSignatureParams.setSigningCertificate(clientParams.getSigningCertificate());
        remoteSignatureParams.setCertificateChain(clientParams.getCertificateChain());
        remoteSignatureParams.setDetachedContents(clientParams.getDetachedContents());

        CertificateToken certToken = DSSUtils.loadCertificate(clientParams.getSigningCertificate().getEncodedCertificate());
        EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forName(certToken.getCertificate().getPublicKey().getAlgorithm());
        remoteSignatureParams.setEncryptionAlgorithm(encryptionAlgorithm);

        Date signingDate = clientParams.getSigningDate();
        remoteBLevelParams.setSigningDate(null == signingDate ? new Date() : signingDate);
        remoteBLevelParams.setClaimedSignerRoles(clientParams.getClaimedSignerRoles());
        remoteBLevelParams.setSignerLocationPostalAddress(clientParams.getSignerLocationPostalAddress());
        remoteBLevelParams.setSignerLocationPostalCode(clientParams.getSignerLocationPostalCode());
        remoteBLevelParams.setSignerLocationLocality(clientParams.getSignerLocationLocality());
        remoteBLevelParams.setSignerLocationStateOrProvince(clientParams.getSignerLocationStateOrProvince());
        remoteBLevelParams.setSignerLocationCountry(clientParams.getSignerLocationCountry());
        remoteBLevelParams.setSignerLocationStreet(clientParams.getSignerLocationStreet());
    }

    public ProfileSignatureParameters findProfileParamsById(String profileId) throws ProfileNotFoundException {
        return signatureDao.findById(profileId);
    }

    private ProfileSignatureParameters findDefaultProfileParams() throws ProfileNotFoundException {
        return signatureDao.findDefault();
    }

    private ProfileTimestampParameters findTimestampProfileParamsById(String profileId) throws ProfileNotFoundException {
        return timestampDao.findById(profileId);
    }

    private ProfileTimestampParameters findDefaultTimestampProfileParams() throws ProfileNotFoundException {
        return timestampDao.findDefault();
    }

}
