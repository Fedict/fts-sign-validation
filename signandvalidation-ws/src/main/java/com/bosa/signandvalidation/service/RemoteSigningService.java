package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.DataToSignDTO;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import lombok.Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class RemoteSigningService {

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

        @Data
        class SignDigestInDTO {
            private byte[][] digests;
            private String digestAlgorithm;
            private String sad;
        }

        byte[][] signedDigests = new byte[dataToSign.length][];
        for(int i = 0; i < dataToSign.length; i++) {
            SignDigestInDTO dto = new SignDigestInDTO();
            dto.setSad(sad);
            dto.setDigestAlgorithm(dataToSign[0].getDigestAlgorithm().getName());
            dto.setDigests(new byte [][] { dataToSign[i].getDigest() });
            signedDigests[i] = new RestTemplate().postForObject(signDigestsOpURL, dto, byte[][].class)[0];
        }
        return signedDigests;
    }

    /*****************************************************************************************/
}
