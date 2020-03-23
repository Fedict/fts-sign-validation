package com.zetes.projects.bosa.signandvalidation.service;

import com.zetes.projects.bosa.signandvalidation.model.IndicationsDTO;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import static eu.europa.esig.dss.enumerations.Indication.PASSED;
import static eu.europa.esig.dss.enumerations.Indication.TOTAL_PASSED;

@Service
public class ReportsService {

    private static final Logger LOG = LoggerFactory.getLogger(ReportsService.class);

    public IndicationsDTO getIndicationsDTO(CertificateReportsDTO certificateReportsDTO) {
        LOG.info(("Getting indications for certificate report..."));
        SimpleCertificateReport simpleCertificateReport = new SimpleCertificateReport(certificateReportsDTO.getSimpleCertificateReport());

        for (String certId : simpleCertificateReport.getCertificateIds()) {
            if (!simpleCertificateReport.getCertificateIndication(certId).equals(PASSED)) {
                return new IndicationsDTO(simpleCertificateReport.getCertificateIndication(certId),
                        simpleCertificateReport.getCertificateSubIndication(certId));
            }
        }

        return new IndicationsDTO(PASSED);
    }

    public boolean isValidSignature(WSReportsDTO reportsDto) {
        return reportsDto.getSimpleReport().getSignature().get(0).getIndication() == TOTAL_PASSED;
    }

    public Indication getIndication(WSReportsDTO reportsDto) {
        return reportsDto.getSimpleReport().getSignature().get(0).getIndication();
    }

    public SubIndication getSubIndication(WSReportsDTO reportsDto) {
        return reportsDto.getSimpleReport().getSignature().get(0).getSubIndication();
    }

}
