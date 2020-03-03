package com.zetes.projects.bosa.signandvalidation.service;

import com.zetes.projects.bosa.signandvalidation.model.IndicationsDTO;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import org.springframework.stereotype.Service;

import static eu.europa.esig.dss.enumerations.Indication.PASSED;

@Service
public class ReportsService {

    public IndicationsDTO getIndicationsDTO(CertificateReportsDTO certificateReportsDTO) {
        SimpleCertificateReport simpleCertificateReport = new SimpleCertificateReport(certificateReportsDTO.getSimpleCertificateReport());

        for (String certId : simpleCertificateReport.getCertificateIds()) {
            if (!simpleCertificateReport.getCertificateIndication(certId).equals(PASSED)) {
                return new IndicationsDTO(simpleCertificateReport.getCertificateIndication(certId),
                        simpleCertificateReport.getCertificateSubIndication(certId));
            }
        }

        return new IndicationsDTO(PASSED);
    }

}
