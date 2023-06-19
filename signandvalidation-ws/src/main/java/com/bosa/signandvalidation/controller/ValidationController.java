package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.exceptions.IllegalSignatureFormatException;
import com.bosa.signandvalidation.model.*;
import com.bosa.signandvalidation.service.ReportsService;
import com.bosa.signandvalidation.service.BosaRemoteDocumentValidationService;
import com.bosa.signandvalidation.config.ErrorStrings;

import static com.bosa.signandvalidation.exceptions.Utils.logAndThrowEx;
import static eu.europa.esig.dss.enumerations.Indication.PASSED;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.diagnostic.jaxb.*;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlToken;
import eu.europa.esig.dss.ws.cert.validation.common.RemoteCertificateValidationService;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.io.Serializable;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import static eu.europa.esig.dss.i18n.MessageTag.BBB_ICS_ISASCP_ANS;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@RestController
@RequestMapping(value = "/validation")
public class ValidationController extends ControllerBase implements ErrorStrings {

    @Autowired
    private BosaRemoteDocumentValidationService remoteDocumentValidationService;

    @Autowired
    private RemoteCertificateValidationService remoteCertificateValidationService;

    @Autowired
    private ReportsService reportsService;

    @GetMapping(value = "/ping", produces = TEXT_PLAIN_VALUE)
    public String ping() {
        return "pong";
    }

    @PostMapping(value = "/validateSignature", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public SignatureIndicationsDTO validateSignature(@RequestBody DataToValidateDTO toValidate) throws IOException {
        WSReportsDTO report = validateSignatureFull(toValidate);
        SignatureIndicationsDTO signDto = reportsService.getSignatureIndicationsDto(report);
        signDto.setNormalizedReport(getNormalizedReport(report));

        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(XmlReportRoot.class);
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            StringWriter sw = new StringWriter();
            XmlReportRoot root = new XmlReportRoot();
            root.setReport(report.getDetailedReport());
            jaxbMarshaller.marshal(root, sw);
            signDto.setReport(sw.toString());
            logger.info("ValidateSignature is finished");
        } catch(Exception e) {
            throw new ResponseStatusException(INTERNAL_SERVER_ERROR, "Cannot render Detailed Signature report");
        }

        return signDto;
    }

    @PostMapping(value = "/validateSignatureFull", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public WSReportsDTO validateSignatureFull(@RequestBody DataToValidateDTO toValidate) {
        if (toValidate.getSignedDocument() == null)
            logAndThrowEx(BAD_REQUEST, NO_DOC_TO_VALIDATE, null, null);

        try {
            WSReportsDTO reportsDto = remoteDocumentValidationService.validateDocument(toValidate.getSignedDocument(), toValidate.getOriginalDocuments(), toValidate.getPolicy());
            if (toValidate.getLevel() != null && reportsDto.getDiagnosticData() != null) {
                checkSignatures(toValidate.getLevel(), reportsDto);
            }
            logger.info("ValidateSignatureFull is finished");
            return reportsDto;
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } catch (IllegalSignatureFormatException e) {
            logAndThrowEx(BAD_REQUEST, INVALID_SIGNATURE_LEVEL, e);
        }
        return null; // We won't get here
    }

    private void checkSignatures(SignatureLevel level, WSReportsDTO reportsDto) throws IllegalSignatureFormatException {
        List<XmlSignature> signatures = reportsDto.getDiagnosticData().getSignatures();
        if (signatures != null)  {
            for (XmlSignature signature : signatures) {
                if (!level.equals(signature.getSignatureFormat())) {
                    throw new IllegalSignatureFormatException("Was : " + signature.getSignatureFormat() + ", expected :" + level);
                }
            }
        }
    }

    public static NormalizedReport getNormalizedReport(WSReportsDTO report) {
        NormalizedReport result = new NormalizedReport();
        List<NormalizedSignatureInfo> signatures = result.getSignatures();

        for(Serializable signOrTsOrCert : report.getDetailedReport().getSignatureOrTimestampOrCertificate()) {
            if (!(signOrTsOrCert instanceof eu.europa.esig.dss.detailedreport.jaxb.XmlSignature)) continue;
            eu.europa.esig.dss.detailedreport.jaxb.XmlSignature signature = (eu.europa.esig.dss.detailedreport.jaxb.XmlSignature) signOrTsOrCert;

            NormalizedSignatureInfo si = new NormalizedSignatureInfo();
            si.setQualified(SignatureQualification.QESIG.equals(signature.getValidationSignatureQualification().getSignatureQualification()));
            XmlConclusion conclusion = signature.getConclusion();
            if (conclusion != null) {
                if (Indication.TOTAL_PASSED.equals(conclusion.getIndication())) {
                    si.setValid(true);
                    List<XmlMessage> warnings = signature.getValidationProcessBasicSignature().getConclusion().getWarnings();
                    for(XmlMessage warning : warnings) {
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

    private static void getSimpleReportInfo(NormalizedSignatureInfo si, XmlSimpleReport simpleReport, String id) {
        for (XmlToken signatureOrTS : simpleReport.getSignatureOrTimestamp()) {
            if (!(signatureOrTS instanceof eu.europa.esig.dss.simplereport.jaxb.XmlSignature)) continue;
            eu.europa.esig.dss.simplereport.jaxb.XmlSignature simpleSignature = (eu.europa.esig.dss.simplereport.jaxb.XmlSignature) signatureOrTS;

            if (simpleSignature.getId().equals(id)) {
                si.setClaimedSigningTime(simpleSignature.getSigningTime());
                si.setBestSigningTime(simpleSignature.getBestSignatureTime());
                break;
            }
        }
    }

    private static void getDiagnosticInfo(NormalizedSignatureInfo si, XmlDiagnosticData diagData, String id) {
        for (XmlSignature diagSignature : diagData.getSignatures()) {
            if (diagSignature.getId().equals(id)) {
                si.setSignatureFormat(diagSignature.getSignatureFormat().name());
                XmlCertificate signingCert = diagSignature.getSigningCertificate().getCertificate();
                si.setSignerCommonName(signingCert.getCommonName());
                if (!isNonRepudiationCert(signingCert)) si.setQualified(false);
                break;
            }
        }
    }

    private static boolean isNonRepudiationCert(XmlCertificate cert) {
        for(XmlCertificateExtension ext : cert.getCertificateExtensions()) {
            if (!(ext instanceof XmlKeyUsages)) continue;
            List<KeyUsageBit> keyUsageBits = ((XmlKeyUsages)ext).getKeyUsageBit();
            if (keyUsageBits.contains(KeyUsageBit.NON_REPUDIATION)) {
                return true;
            }
        }
        return false;
    }

    @PostMapping(value = "/validateCertificate", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public CertificateIndicationsDTO validateCertificate(@RequestBody CertificateToValidateDTO toValidate) {
        if (toValidate.getCertificate() == null)
            logAndThrowEx(BAD_REQUEST, NO_CERT_TO_VALIDATE, null, null);

        try {
            CertificateReportsDTO certificateReportsDTO = remoteCertificateValidationService.validateCertificate(
                new eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO(
			toValidate.getCertificate(), toValidate.getCertificateChain(), toValidate.getValidationTime()));
            CertificateIndicationsDTO rv = reportsService.getCertificateIndicationsDTO(certificateReportsDTO, toValidate.getExpectedKeyUsage());
            if(rv.getIndication() != PASSED) {
                certificateReportsDTO.getSimpleCertificateReport().getChain().forEach(item -> {
                    logger.log(Level.SEVERE, "Certificate validation indication = {0}; certificate ID = {1}, issuer ID = {2}", new Object[]{rv.getIndication().toString(), item.getId(), item.getIssuerId()});
                });
            }
            logger.info("ValidateCertificate is finished");
            return rv;
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = "/validateCertificateFull", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public CertificateReportsDTO validateCertificateFull(@RequestBody CertificateToValidateDTO toValidate) {
        if (toValidate.getCertificate() == null)
            logAndThrowEx(BAD_REQUEST, NO_CERT_TO_VALIDATE, null, null);

        try {
            CertificateReportsDTO result = remoteCertificateValidationService.validateCertificate(
                new eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO(
			toValidate.getCertificate(), toValidate.getCertificateChain(), toValidate.getValidationTime()));
            logger.info("ValidateCertificateFull is finished");
            return result;
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = "/validateCertificates", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public IndicationsListDTO validateCertificates(@RequestBody List<CertificateToValidateDTO> toValidateList) {
        try {
            List<CertificateIndicationsDTO> indications = new ArrayList<>();

            for (CertificateToValidateDTO toValidate : toValidateList) {
                indications.add(validateCertificate(toValidate));
            }

            logger.info("ValidateCertificates is finished");
            return new IndicationsListDTO(indications);
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    private static class XmlReportRoot {

        private XmlDetailedReport report;

        public void setReport(XmlDetailedReport report) {
            this.report = report;
        }
    }
}
