package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.CertificateIndicationsDTO;
import com.bosa.signandvalidation.model.SignatureIndicationsDTO;
import com.bosa.signandvalidation.config.ErrorStrings;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlChainItem;
import eu.europa.esig.dss.simplereport.jaxb.*;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Date;
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
            if (!PASSED.equals(item.getIndication())) {
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

    // Remark : the name "getSignatureIndicationsDto" should probably be "getSignatureAndTsIndicationsDto"...
    // or the Timestamps should be filtered from the "getSignatureOrTimestamp" list
    public SignatureIndicationsDTO getSignatureIndicationsDto(WSReportsDTO reportsDto) {
        if (reportsDto.getSimpleReport().getSignaturesCount() == 0) {
            return new SignatureIndicationsDTO(INDETERMINATE, SIGNED_DATA_NOT_FOUND);
        }

        for (XmlToken xmlToken : reportsDto.getSimpleReport().getSignatureOrTimestamp()) {
            SignatureIndicationsDTO dto = getRevokedIndication(xmlToken);
            if (dto != null) return dto;
        }

        return new SignatureIndicationsDTO(TOTAL_PASSED);
    }

    // This method is needed to allow signing the "unsignable PDF" that had a pre-existing, not "TOTAL_PASSED" Timestamp
    // This validation will locate the newly added signature and only check the indications for that signature
    public SignatureIndicationsDTO getLatestSignatureIndicationsDto(WSReportsDTO reportsDto, Date after) {
        XmlSignature xmlSignature = getLatestSignature(reportsDto.getSimpleReport(), after);
        if (xmlSignature == null) {
            return new SignatureIndicationsDTO(INDETERMINATE, SIGNED_DATA_NOT_FOUND);
        }

        SignatureIndicationsDTO dto = getRevokedIndication(xmlSignature);
        return dto == null ? new SignatureIndicationsDTO(TOTAL_PASSED) : dto;
    }

    // In the list SignatureOrTimestamp find a signature info based on the following criteria:
    //   - The info is about the most recent signature
    //   - The signature occurred after (or at the same time as) the input parameter "minTime"
    // If none is found return null
    private static XmlSignature getLatestSignature(XmlSimpleReport simpleReport, Date minTime) {
        XmlSignature latestSignature =  null;
        for(XmlToken signatureOrTimestamp : simpleReport.getSignatureOrTimestamp()) {
            if (signatureOrTimestamp instanceof XmlSignature) {
                XmlSignature signature = (XmlSignature)signatureOrTimestamp;
                Date bestSignatureTime = signature.getBestSignatureTime();
                if (bestSignatureTime.compareTo(minTime) >= 0 && (latestSignature == null || bestSignatureTime.compareTo(latestSignature.getBestSignatureTime()) >= 0)) {
                    latestSignature = signature;
                }
            }
        }
        return latestSignature;
    }

    private static SignatureIndicationsDTO getRevokedIndication(XmlToken xmlToken) {
        if (!xmlToken.getIndication().equals(TOTAL_PASSED)) {
            // If a cert (most probably the signing cert but it seems impossible to get this
            // info from the reports) has been revoked then we'll return a special error
            boolean hasRevocation = findRevocation(xmlToken.getAdESValidationDetails()) ||
                    findRevocation(xmlToken.getQualificationDetails());

            return new SignatureIndicationsDTO(xmlToken.getIndication(),
                    hasRevocation ? CERT_REVOKED : xmlToken.getSubIndication().toString());
        }
        return null;
    }

    private static boolean findRevocation(XmlDetails details) {
        if (details == null || details.getError() == null) return false;

        for (XmlMessage error : details.getError()) {
            // The error says "The certificate is revoked!" but to make it
            // a bit more robust let's just check for 'certificate' and 'revoked'
            // Note: perhaps it's be better to check the Conclusion of the SIGNATURE
            // BasicBuildingBlock that has SubIndication "REVOKED_NO_POE"
            if (error.getValue().contains("certificate") && error.getValue().contains("revoked")) return true;
        }
        return false;
    }
}
