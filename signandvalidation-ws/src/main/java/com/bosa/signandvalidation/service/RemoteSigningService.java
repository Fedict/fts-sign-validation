package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.DataToSignDTO;
import com.bosa.signandvalidation.model.remotesign.CredentialsListDTO;
import com.bosa.signandvalidation.model.remotesign.GetCredentialsListDTO;
import com.bosa.signandvalidation.model.remotesign.SignHashesDTO;
import com.bosa.signandvalidation.model.remotesign.SignedHashesDTO;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class RemoteSigningService extends RemoteSigningInterface {

    private static final Logger LOG = LoggerFactory.getLogger(RemoteSigningService.class);

    private String sadOpURL;
    private String certificatesOpURL;
    private String signDigestsOpURL;

    /*****************************************************************************************/

    public RemoteSigningService(String sadOpURL, String certificatesOpURL, String signDigestsOpURL)
    {
        this.sadOpURL               = sadOpURL;
        this.signDigestsOpURL       = signDigestsOpURL;
        this.certificatesOpURL      = certificatesOpURL;
    }

    /*****************************************************************************************/

    public String getSadFromCode(String code) {

        return new RestTemplate().getForObject(sadOpURL + code, String.class);
    }

    /*****************************************************************************************/

    public List<RemoteCertificate> getCertificatesFromSad(String sad) {

        String [] certificates = new RestTemplate().getForObject(certificatesOpURL + sad, String[].class);
        List<RemoteCertificate> certs = new ArrayList<>();
        Base64.Decoder decoder = Base64.getDecoder();
        for(int i = 0; i < certificates.length; i++) {
            certs.add(new RemoteCertificate(decoder.decode(certificates[i])));
        }
        return certs;
    }

    /*****************************************************************************************/

    public byte[][] signDigests(String sad, DataToSignDTO[] dataToSign) {

        byte[][] signedDigests = new byte[dataToSign.length][];
        for(int i = 0; i < dataToSign.length; i++) {
            SignDigestInDTO dto = new SignDigestInDTO(new byte [][] { dataToSign[i].getDigest() }, dataToSign[i].getDigestAlgorithm().getName(), sad);
            signedDigests[i] = new RestTemplate().postForObject(signDigestsOpURL, dto, byte[][].class)[0];
        }
        return signedDigests;
    }

    /*****************************************************************************************/

    public byte[] signDigest(String sad, DigestAlgorithm digestAlgorithm, byte [] bytesToSign) {
        return signDigests(sad, new DataToSignDTO[]{ new DataToSignDTO(digestAlgorithm, bytesToSign, null)} )[0];
    }

    /*****************************************************************************************/

    @Data
    @AllArgsConstructor
    class SignDigestInDTO {
        private byte[][] digests;
        private String digestAlgorithm;
        private String sad;
    }

    /*****************************************************************************************/
    @Override
    public String getAccessToken() {
        return "";
    }

    /*****************************************************************************************/

    @Override
    public CredentialsListDTO getCredentialsList(GetCredentialsListDTO in) {
        return null;
    }

    /*****************************************************************************************/

    @Override
    public SignedHashesDTO signSignHashes(SignHashesDTO in) {
        return null;
    }

    /*****************************************************************************************/
}
