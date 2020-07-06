package com.zetes.projects.bosa.signingconfigurator.service;

import com.zetes.projects.bosa.signingconfigurator.dao.ProfileSignatureParametersDao;
import com.zetes.projects.bosa.signingconfigurator.exception.NullParameterException;
import com.zetes.projects.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.zetes.projects.bosa.signingconfigurator.model.ProfileSignatureParameters;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteBLevelParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SigningConfiguratorService {

    @Autowired
    ProfileSignatureParametersDao dao;

    @Autowired
    OnlineTSPSource tspSource;

    public RemoteSignatureParameters getSignatureParams(String profileId, ClientSignatureParameters clientParams) throws ProfileNotFoundException, NullParameterException {
        if (clientParams == null || clientParams.getSigningCertificate() == null || clientParams.getSigningDate() == null) {
            throw new NullParameterException("Parameters should not be null");
        }

        ProfileSignatureParameters profileParams;
        if (profileId == null) {
            profileParams = findDefaultProfileParams();
        } else {
            profileParams = findProfileParamsById(profileId);
        }

        tspSource.setTspServer(profileParams.getTspServer());
        return fillRemoteSignatureParams(clientParams, profileParams);
    }

    public RemoteSignatureParameters getExtensionParams(String profileId, List<RemoteDocument> detachedContents) throws ProfileNotFoundException {
        ProfileSignatureParameters profileParams;
        if (profileId == null) {
            profileParams = findDefaultProfileParams();
        } else {
            profileParams = findProfileParamsById(profileId);
        }

        tspSource.setTspServer(profileParams.getTspServer());
        return fillExtensionParams(detachedContents, profileParams);
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
        remoteSignatureParams.setSignaturePackaging(profileParams.getSignaturePackaging());
        remoteSignatureParams.setDigestAlgorithm(profileParams.getDigestAlgorithm());
        remoteSignatureParams.setMaskGenerationFunction(profileParams.getMaskGenerationFunction());
        remoteSignatureParams.setReferenceDigestAlgorithm(profileParams.getReferenceDigestAlgorithm());
    }

    private void fillClientParams(ClientSignatureParameters clientParams, RemoteSignatureParameters remoteSignatureParams, RemoteBLevelParameters remoteBLevelParams) {
        remoteSignatureParams.setSigningCertificate(clientParams.getSigningCertificate());
        remoteSignatureParams.setCertificateChain(clientParams.getCertificateChain());
        remoteSignatureParams.setDetachedContents(clientParams.getDetachedContents());

        EncryptionAlgorithm encryptionAlgorithm = DSSUtils.loadCertificate(clientParams.getSigningCertificate().getEncodedCertificate()).getSignatureAlgorithm().getEncryptionAlgorithm();
        remoteSignatureParams.setEncryptionAlgorithm(encryptionAlgorithm);

        remoteBLevelParams.setSigningDate(clientParams.getSigningDate());
        remoteBLevelParams.setClaimedSignerRoles(clientParams.getClaimedSignerRoles());
        remoteBLevelParams.setSignerLocationPostalAddress(clientParams.getSignerLocationPostalAddress());
        remoteBLevelParams.setSignerLocationPostalCode(clientParams.getSignerLocationPostalCode());
        remoteBLevelParams.setSignerLocationLocality(clientParams.getSignerLocationLocality());
        remoteBLevelParams.setSignerLocationStateOrProvince(clientParams.getSignerLocationStateOrProvince());
        remoteBLevelParams.setSignerLocationCountry(clientParams.getSignerLocationCountry());
        remoteBLevelParams.setSignerLocationStreet(clientParams.getSignerLocationStreet());
    }

    private ProfileSignatureParameters findProfileParamsById(String profileId) throws ProfileNotFoundException {
        return dao.findById(profileId).orElseThrow(() -> new ProfileNotFoundException(String.format("%s not found", profileId)));
    }

    private ProfileSignatureParameters findDefaultProfileParams() throws ProfileNotFoundException {
        return dao.findDefault().orElseThrow(() -> new ProfileNotFoundException("Default profile not found"));
    }

}
