package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.DataToSignDTO;
import com.bosa.signandvalidation.model.remotesign.CredentialsListDTO;
import com.bosa.signandvalidation.model.remotesign.GetCredentialsListDTO;
import com.bosa.signandvalidation.model.remotesign.SignHashesDTO;
import com.bosa.signandvalidation.model.remotesign.SignedHashesDTO;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import java.util.List;

public abstract class RemoteSigningInterface {

    public abstract List<RemoteCertificate> getCertificatesFromAccessToken(String accessToken);

    public abstract String getAccoutStatus(String accessToken);
    public abstract CredentialsListDTO getCredentialsList(GetCredentialsListDTO in);
    public abstract SignedHashesDTO signSignHashes(SignHashesDTO in);


    public abstract String getSadFromCode(String code);
    public abstract List<RemoteCertificate> getCertificates(String accessToken);
    public abstract byte[][] signDigests(String sad, DataToSignDTO[] dataToSign);
}
