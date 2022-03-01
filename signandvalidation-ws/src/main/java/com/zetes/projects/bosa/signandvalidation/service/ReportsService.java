package com.zetes.projects.bosa.signandvalidation.service;

import com.zetes.projects.bosa.signandvalidation.model.CertificateIndicationsDTO;
import com.zetes.projects.bosa.signandvalidation.model.SignatureIndicationsDTO;
import com.zetes.projects.bosa.signandvalidation.config.ErrorStrings;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlChainItem;
import eu.europa.esig.dss.simplereport.jaxb.XmlToken;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

import static eu.europa.esig.dss.enumerations.Indication.*;
import static eu.europa.esig.dss.enumerations.SubIndication.SIGNED_DATA_NOT_FOUND;

@Service
public class ReportsService implements ErrorStrings {

    private static final Logger LOG = LoggerFactory.getLogger(ReportsService.class);

    public CertificateIndicationsDTO getCertificateIndicationsDTO(CertificateReportsDTO certificateReportsDTO, KeyUsageBit expectedKeyUsage) {
        LOG.info(("Getting indications for certificate report..."));
        List<XmlChainItem> chain = certificateReportsDTO.getSimpleCertificateReport().getChain();
        String firstCommonName = chain.get(0).getSubject().getCommonName();
        boolean keyUsageCheckOk = chain.get(0).getKeyUsages().contains(expectedKeyUsage);

        for (XmlChainItem item : chain) {
            if (!item.getIndication().equals(PASSED)) {
                return new CertificateIndicationsDTO(
                        firstCommonName,
                        item.getIndication(),
                        item.getSubIndication(),
                        keyUsageCheckOk
                );
            }
        }

        return new CertificateIndicationsDTO(firstCommonName, PASSED, keyUsageCheckOk);
    }

    public SignatureIndicationsDTO getSignatureIndicationsDto(WSReportsDTO reportsDto) {
        if (reportsDto.getSimpleReport().getSignaturesCount() == 0) {
            return new SignatureIndicationsDTO(INDETERMINATE, SIGNED_DATA_NOT_FOUND);
        }

        for (XmlToken xmlToken : reportsDto.getSimpleReport().getSignatureOrTimestamp()) {
            if (!xmlToken.getIndication().equals(TOTAL_PASSED)) {
/*
                // If a cert (most probably the signing cert but it seems impossible to get this
                // info from the reports) has been revoked then we'll return a special error
                for (String err : xmlToken.getErrors()) {
                    // The error says "The certificate is revoked!" but to make it
                    // a bit more robust let's just check for 'certificate' and 'revoked'
                    // Note: perhaps it's be better to check the Conclusion of the SIGNATURE
                    // BasicBuildingBlock that has SubIndication "REVOKED_NO_POE"
                    if (err.contains("certificate") && err.contains("revoked"))
            			return new SignatureIndicationsDTO(xmlToken.getIndication(), CERT_REVOKED);
                }
 */

                return new SignatureIndicationsDTO(xmlToken.getIndication(), xmlToken.getSubIndication());
            }
        }

        return new SignatureIndicationsDTO(TOTAL_PASSED);
    }

}
