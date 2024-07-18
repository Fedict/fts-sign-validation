package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.DataToSignDTO;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import java.util.List;

public abstract class RemoteSigningInterface {

    public abstract String getSadFromCode(String code);
    public abstract List<RemoteCertificate> getCertificatesFromSad(String sad);
    public abstract byte[][] signDigests(String sad, DataToSignDTO[] dataToSign);

    public byte[] signDigest(String sad, DigestAlgorithm digestAlgorithm, byte [] bytesToSign) {
        return signDigests(sad, new DataToSignDTO[]{ new DataToSignDTO(digestAlgorithm, bytesToSign, null)} )[0];
    }
}
