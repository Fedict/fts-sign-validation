package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.*;
import com.bosa.signandvalidation.config.ErrorStrings;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateExtension;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlKeyUsages;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlChainItem;
import eu.europa.esig.dss.simplereport.jaxb.*;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.io.Serializable;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import static eu.europa.esig.dss.enumerations.Indication.*;
import static eu.europa.esig.dss.enumerations.SubIndication.SIGNED_DATA_NOT_FOUND;
import static eu.europa.esig.dss.i18n.MessageTag.BBB_ICS_ISASCP_ANS;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@Service
public class ReportsService implements ErrorStrings {

    private static final SimpleDateFormat reportDateTimeFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

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

    public SignatureIndicationsDTO getSignatureIndicationsAndReportsDto(SignatureFullValiationDTO reportsDto) {
        SignatureIndicationsDTO dto = getSignatureIndicationsDto(reportsDto);

        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(ReportsService.XmlReportRoot.class);
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            StringWriter sw = new StringWriter();
            ReportsService.XmlReportRoot root = new ReportsService.XmlReportRoot();
            root.setReport(reportsDto.getDetailedReport());
            jaxbMarshaller.marshal(root, sw);
            dto.setReport(sw.toString());
        } catch(Exception e) {
            throw new ResponseStatusException(INTERNAL_SERVER_ERROR, "Cannot render Detailed Signature report");
        }
        dto.setNormalizedReport(getNormalizedReport(reportsDto));
        return dto;
    }

    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    private static class XmlReportRoot {

        private XmlDetailedReport report;

        public void setReport(XmlDetailedReport report) {
            this.report = report;
        }
    }

    public SignatureIndicationsDTO getSignatureIndicationsDto(SignatureFullValiationDTO reportsDto) {
        if (reportsDto.getSimpleReport().getSignaturesCount() == 0) {
            return new SignatureIndicationsDTO(INDETERMINATE, SIGNED_DATA_NOT_FOUND);
        }

        for (XmlToken xmlToken : reportsDto.getSimpleReport().getSignatureOrTimestampOrEvidenceRecord()) {
            SignatureIndicationsDTO dto = getRevokedIndication(xmlToken);
            if (dto != null) return dto;
        }

        return new SignatureIndicationsDTO(TOTAL_PASSED);
    }

    // This method is needed to allow signing the "unsignable PDF" that had a pre-existing, not "TOTAL_PASSED" Timestamp
    // This validation will locate the newly added signature and only check the indications for that signature
    public SignatureIndicationsDTO getLatestSignatureIndicationsDto(SignatureFullValiationDTO reportsDto, Date after) {
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
        for(XmlToken signatureOrTimestamp : simpleReport.getSignatureOrTimestampOrEvidenceRecord()) {
            if (signatureOrTimestamp instanceof XmlSignature) {
                XmlSignature signature = (XmlSignature)signatureOrTimestamp;
                Date bestSignatureTime = signature.getBestSignatureTime();
                if (bestSignatureTime.compareTo(minTime) >= 0 && (latestSignature == null || bestSignatureTime.compareTo(latestSignature.getBestSignatureTime()) >= 0)) {
                    latestSignature = signature;
                }
            }
        }

        if (latestSignature == null) LOG.error("No latest signature found :" + (System.currentTimeMillis() - minTime.getTime()));

        return latestSignature;
    }

    /*****************************************************************************************/

    private static SignatureIndicationsDTO getRevokedIndication(XmlToken xmlToken) {
        if (!xmlToken.getIndication().equals(TOTAL_PASSED)) {
            // If a cert (most probably the signing cert but it seems impossible to get this
            // info from the reports) has been revoked then we'll return a special error
            boolean hasRevocation = findRevocation(xmlToken.getAdESValidationDetails()) ||
                    findRevocation(xmlToken.getQualificationDetails());

            return new SignatureIndicationsDTO(xmlToken.getIndication(),
                    hasRevocation ? CERT_REVOKED : xmlToken.getSubIndication() == null ? "" : xmlToken.getSubIndication().toString());
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

    /*****************************************************************************************/

    public NormalizedReport getNormalizedReport(SignatureFullValiationDTO report) {
        NormalizedReport result = new NormalizedReport();
        List<NormalizedSignatureInfo> signatures = result.getSignatures();

        for(Serializable signOrTsOrCert : report.getDetailedReport().getSignatureOrTimestampOrEvidenceRecord()) {
            if (!(signOrTsOrCert instanceof eu.europa.esig.dss.detailedreport.jaxb.XmlSignature)) continue;
            eu.europa.esig.dss.detailedreport.jaxb.XmlSignature signature = (eu.europa.esig.dss.detailedreport.jaxb.XmlSignature) signOrTsOrCert;

            NormalizedSignatureInfo si = new NormalizedSignatureInfo();
            si.setQualified(SignatureQualification.QESIG.equals(signature.getValidationSignatureQualification().getSignatureQualification()));
            XmlConclusion conclusion = signature.getConclusion();
            if (conclusion != null) {
                if (Indication.TOTAL_PASSED.equals(conclusion.getIndication())) {
                    si.setValid(true);
                    List<eu.europa.esig.dss.detailedreport.jaxb.XmlMessage> warnings = signature.getValidationProcessBasicSignature().getConclusion().getWarnings();
                    for(eu.europa.esig.dss.detailedreport.jaxb.XmlMessage warning : warnings) {
                        if (BBB_ICS_ISASCP_ANS.equals(warning.getKey()) && "The signed attribute: 'signing-certificate' is absent!".equals(warning.getValue())) {
                            si.setMissingSigningCert(true);
                            break;
                        }
                    }
                } else si.setSubIndication(conclusion.getSubIndication().name());
            }
            getSimpleReportInfo(si, report.getSimpleReport(), signature.getId());
            getDiagnosticInfo(si, report.getDiagnosticData(), signature.getId());
            signatures.add(si);
        }

        return  result;
    }

    private void getSimpleReportInfo(NormalizedSignatureInfo si, XmlSimpleReport simpleReport, String id) {
        for (XmlToken signatureOrTS : simpleReport.getSignatureOrTimestampOrEvidenceRecord()) {
            if (!(signatureOrTS instanceof eu.europa.esig.dss.simplereport.jaxb.XmlSignature)) continue;
            eu.europa.esig.dss.simplereport.jaxb.XmlSignature simpleSignature = (eu.europa.esig.dss.simplereport.jaxb.XmlSignature) signatureOrTS;

            if (simpleSignature.getId().equals(id)) {
                si.setClaimedSigningTime(simpleSignature.getSigningTime());
                si.setBestSigningTime(simpleSignature.getBestSignatureTime());
                break;
            }
        }
    }

    private void getDiagnosticInfo(NormalizedSignatureInfo si, XmlDiagnosticData diagData, String id) {
        for (eu.europa.esig.dss.diagnostic.jaxb.XmlSignature diagSignature : diagData.getSignatures()) {
            if (diagSignature.getId().equals(id)) {
                si.setSignatureFormat(SignatureLevel.fromDss(diagSignature.getSignatureFormat()));
                eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCert = diagSignature.getSigningCertificate().getCertificate();
                si.setSignerCommonName(signingCert.getCommonName());
                if (!isNonRepudiationCert(signingCert)) si.setQualified(false);
                break;
            }
        }
    }

    private boolean isNonRepudiationCert(eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate cert) {
        for(XmlCertificateExtension ext : cert.getCertificateExtensions()) {
            if (!(ext instanceof XmlKeyUsages)) continue;
            List<KeyUsageBit> keyUsageBits = ((XmlKeyUsages)ext).getKeyUsageBit();
            if (keyUsageBits.contains(KeyUsageBit.NON_REPUDIATION)) {
                return true;
            }
        }
        return false;
    }

    /*****************************************************************************************/

    public String createJSONReport(RemoteSignatureParameters parameters, SignatureFullValiationDTO reportsDto) throws IOException {
        // Instead of saving the entire report, create our own report containing the simple/detailed/normalized reports and the signing cert

        ReportDTO reportDto = new ReportDTO(reportsDto.getSimpleReport(),
                reportsDto.getDetailedReport(),
                parameters.getSigningCertificate().getEncodedCertificate(),
                getNormalizedReport(reportsDto));

        StringWriter out = new StringWriter();
        ObjectMapper mapper = new ObjectMapper();
        mapper.setDateFormat(reportDateTimeFormat);
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        mapper.writeValue(out, reportDto);
        return out.toString();
    }

    /*****************************************************************************************/
}
