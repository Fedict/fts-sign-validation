package com.zetes.projects.bosa.signandvalidation.service;

import com.zetes.projects.bosa.signandvalidation.model.CertificateIndicationsDTO;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlChainItem;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

import static eu.europa.esig.dss.enumerations.Indication.PASSED;
import static eu.europa.esig.dss.enumerations.Indication.TOTAL_PASSED;

@Service
public class ReportsService {

    private static final Logger LOG = LoggerFactory.getLogger(ReportsService.class);

    public CertificateIndicationsDTO getCertificateIndicationsDTO(CertificateReportsDTO certificateReportsDTO, KeyUsageBit expectedKeyUsage) {
        LOG.info(("Getting indications for certificate report..."));
        List<XmlChainItem> chain = certificateReportsDTO.getSimpleCertificateReport().getChain();
        String firstCommonName = chain.get(0).getSubject().getCommonName();
        System.out.println(chain.get(0).getKeyUsages());
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

    public boolean isValidSignature(WSReportsDTO reportsDto) {
        return reportsDto.getSimpleReport().getSignature().get(0).getIndication() == TOTAL_PASSED;
    }

    public Indication getSignatureIndication(WSReportsDTO reportsDto) {
        return reportsDto.getSimpleReport().getSignature().get(0).getIndication();
    }

    public SubIndication getSignatureSubIndication(WSReportsDTO reportsDto) {
        return reportsDto.getSimpleReport().getSignature().get(0).getSubIndication();
    }

}
