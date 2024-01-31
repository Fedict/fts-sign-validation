package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.NormalizedReport;
import com.bosa.signandvalidation.model.NormalizedSignatureInfo;
import com.bosa.signandvalidation.model.SignatureFullValiationDTO;
import com.bosa.signandvalidation.model.SignatureIndicationsDTO;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlKeyUsages;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.simplereport.jaxb.*;
import org.junit.jupiter.api.Test;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static com.bosa.signandvalidation.config.ErrorStrings.CERT_REVOKED;
import static com.bosa.signandvalidation.model.SignatureLevel.PAdES_BASELINE_LTA;
import static eu.europa.esig.dss.enumerations.Indication.*;
import static eu.europa.esig.dss.enumerations.SubIndication.*;
import static org.junit.jupiter.api.Assertions.*;

public class ReportServiceTest {

    private static ReportsService srv = new ReportsService();
    private static Date now = new Date();
    private static Date past = new Date(now.getTime() - 10000);

    @Test
    public void getSignatureIndicationsDtoNoSignatureTest() throws Exception {
        SignatureFullValiationDTO report = new SignatureFullValiationDTO();
        XmlSimpleReport simple = new XmlSimpleReport();
        report.setSimpleReport(simple);
        simple.setSignaturesCount(0);
        SignatureIndicationsDTO dto = srv.getLatestSignatureIndicationsDto(report, past);

        assertEquals(INDETERMINATE, dto.getIndication());
        assertEquals(SIGNED_DATA_NOT_FOUND.name(), dto.getSubIndicationLabel());
    }

    @Test
    public void getSignatureIndicationsDtoOneSignatureTest() throws Exception {
        SignatureFullValiationDTO report = new SignatureFullValiationDTO();
        XmlSimpleReport simple = new XmlSimpleReport();
        report.setSimpleReport(simple);
        simple.setSignaturesCount(1);
        List<XmlToken> signatures = simple.getSignatureOrTimestampOrEvidenceRecord();
        XmlSignature signature = new XmlSignature();
        signature.setBestSignatureTime(now);
        signature.setIndication(TOTAL_PASSED);
        signatures.add(signature);
        SignatureIndicationsDTO dto = srv.getLatestSignatureIndicationsDto(report, past);

        assertEquals(TOTAL_PASSED, dto.getIndication());
    }

    @Test
    public void getSignatureIndicationsDtoOnePassedSignatureTest() throws Exception {
        SignatureFullValiationDTO report = new SignatureFullValiationDTO();
        XmlSimpleReport simple = new XmlSimpleReport();
        report.setSimpleReport(simple);
        simple.setSignaturesCount(1);
        List<XmlToken> signatures = simple.getSignatureOrTimestampOrEvidenceRecord();
        XmlSignature signature = new XmlSignature();
        signature.setBestSignatureTime(now);
        signature.setIndication(PASSED);
        signature.setSubIndication(HASH_FAILURE);
        signatures.add(signature);
        SignatureIndicationsDTO dto = srv.getLatestSignatureIndicationsDto(report, past);
        assertEquals(PASSED, dto.getIndication());
        assertEquals(HASH_FAILURE.name(), dto.getSubIndicationLabel());
    }

    @Test
    public void getSignatureIndicationsDtoRevokedAdesCertTest() throws Exception {
        SignatureFullValiationDTO report = new SignatureFullValiationDTO();
        XmlSimpleReport simple = new XmlSimpleReport();
        report.setSimpleReport(simple);
        simple.setSignaturesCount(1);
        List<XmlToken> signatures = simple.getSignatureOrTimestampOrEvidenceRecord();
        XmlSignature signature = new XmlSignature();
        signature.setBestSignatureTime(now);
        signature.setIndication(PASSED);
        signature.setSubIndication(HASH_FAILURE);
        XmlDetails adesValidation = new XmlDetails();
        XmlMessage xmlMessage = new XmlMessage();
        xmlMessage.setValue("certificate revoked");
        adesValidation.getError().add(xmlMessage);
        signature.setAdESValidationDetails(adesValidation);
        signatures.add(signature);
        SignatureIndicationsDTO dto = srv.getLatestSignatureIndicationsDto(report, past);

        assertEquals(PASSED, dto.getIndication());
        assertEquals(CERT_REVOKED, dto.getSubIndicationLabel());
    }

    @Test
    public void getSignatureIndicationsDtoRevokedQualifCertTest() throws Exception {
        SignatureFullValiationDTO report = new SignatureFullValiationDTO();
        XmlSimpleReport simple = new XmlSimpleReport();
        report.setSimpleReport(simple);
        simple.setSignaturesCount(1);
        List<XmlToken> signatures = simple.getSignatureOrTimestampOrEvidenceRecord();
        XmlSignature signature = new XmlSignature();
        signature.setBestSignatureTime(now);
        signature.setIndication(PASSED);
        signature.setSubIndication(HASH_FAILURE);
        XmlDetails qualifValidation = new XmlDetails();
        XmlMessage xmlMessage = new XmlMessage();
        xmlMessage.setValue("certificate revoked");
        qualifValidation.getError().add(xmlMessage);
        signature.setQualificationDetails(qualifValidation);
        signatures.add(signature);
        SignatureIndicationsDTO dto = srv.getLatestSignatureIndicationsDto(report, past);

        assertEquals(PASSED, dto.getIndication());
        assertEquals(CERT_REVOKED, dto.getSubIndicationLabel());
    }

    @Test
    public void getSignatureIndicationsDtoNoRevokedCertTest() throws Exception {
        SignatureFullValiationDTO report = new SignatureFullValiationDTO();
        XmlSimpleReport simple = new XmlSimpleReport();
        report.setSimpleReport(simple);
        simple.setSignaturesCount(1);
        List<XmlToken> signatures = simple.getSignatureOrTimestampOrEvidenceRecord();
        XmlSignature signature = new XmlSignature();
        signature.setBestSignatureTime(now);
        signature.setIndication(PASSED);
        signature.setSubIndication(HASH_FAILURE);
        XmlDetails qualifValidation = new XmlDetails();
        XmlMessage xmlMessage = new XmlMessage();
        xmlMessage.setValue("Any other error");
        qualifValidation.getError().add(xmlMessage);
        signature.setQualificationDetails(qualifValidation);
        signatures.add(signature);
        SignatureIndicationsDTO dto = srv.getLatestSignatureIndicationsDto(report, past);

        assertEquals(PASSED, dto.getIndication());
        assertEquals(HASH_FAILURE.name(), dto.getSubIndicationLabel());
    }

    @Test
    public void getSignatureIndicationsDtoTwoSignTest() throws Exception {
        SignatureFullValiationDTO report = new SignatureFullValiationDTO();
        XmlSimpleReport simple = new XmlSimpleReport();
        report.setSimpleReport(simple);
        simple.setSignaturesCount(2);
        List<XmlToken> signatures = simple.getSignatureOrTimestampOrEvidenceRecord();
        XmlSignature signature = new XmlSignature();
        signature.setIndication(PASSED);
        signature.setSubIndication(HASH_FAILURE);
        signature.setBestSignatureTime(now);
        XmlDetails adesValidation = new XmlDetails();
        signature.setAdESValidationDetails(adesValidation);
        signatures.add(signature);
        signature = new XmlSignature();
        signature.setIndication(TOTAL_PASSED);
        signature.setBestSignatureTime(new Date(now.getTime() + 20));
        signatures.add(signature);
        SignatureIndicationsDTO dto = srv.getLatestSignatureIndicationsDto(report, now);

        assertEquals(TOTAL_PASSED, dto.getIndication());
    }
    @Test
    public void normalizedReportTest() throws Exception {
        SignatureFullValiationDTO report = new SignatureFullValiationDTO();

        String theID = "ID1";
        String theCommonName = "TheSigner";

        XmlSimpleReport simple = new XmlSimpleReport();
        report.setSimpleReport(simple);

        XmlDiagnosticData diagData = new XmlDiagnosticData();
        report.setDiagnosticData(diagData);
        List<eu.europa.esig.dss.diagnostic.jaxb.XmlSignature> diagSignatures = new ArrayList<>();
        diagData.setSignatures(diagSignatures);
        eu.europa.esig.dss.diagnostic.jaxb.XmlSignature diagSignature = new eu.europa.esig.dss.diagnostic.jaxb.XmlSignature();
        diagSignatures.add(diagSignature);
        diagSignature.setId(theID);
        diagSignature.setSignatureFormat(PAdES_BASELINE_LTA.toDSS());
        XmlSigningCertificate signingCert = new XmlSigningCertificate();
        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate theCert = new eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate();
        XmlKeyUsages usages = new XmlKeyUsages();
        usages.getKeyUsageBit().add(KeyUsageBit.NON_REPUDIATION);
        theCert.getCertificateExtensions().add(usages);

        theCert.setCommonName(theCommonName);
        signingCert.setCertificate(theCert);
        diagSignature.setSigningCertificate(signingCert);

        XmlDetailedReport detailedReport = new XmlDetailedReport();
        report.setDetailedReport(detailedReport);
        List<Serializable> sigList = detailedReport.getSignatureOrTimestampOrEvidenceRecord();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature sig = new eu.europa.esig.dss.detailedreport.jaxb.XmlSignature();
        sigList.add(sig);
        sig.setId(theID);
        XmlValidationSignatureQualification sigValQual= new XmlValidationSignatureQualification();
        sig.setValidationSignatureQualification(sigValQual);
        sigValQual.setSignatureQualification(SignatureQualification.QESIG);
        XmlConclusion conclusion = new XmlConclusion();
        sig.setConclusion(conclusion);
        conclusion.setIndication(TOTAL_PASSED);
        XmlValidationProcessBasicSignature validationBasic = new XmlValidationProcessBasicSignature();
        sig.setValidationProcessBasicSignature(validationBasic);
        XmlConclusion basicConclusion = new XmlConclusion();
        validationBasic.setConclusion(basicConclusion);
        basicConclusion.getWarnings();

        NormalizedReport dto = srv.getNormalizedReport(report);

        assertEquals(1, dto.getSignatures().size());
        NormalizedSignatureInfo theSignature = dto.getSignatures().get(0);
        assertTrue(theSignature.isValid());
        assertTrue(theSignature.isQualified());
        assertFalse(theSignature.isMissingSigningCert());
        assertEquals(PAdES_BASELINE_LTA, theSignature.getSignatureFormat());
        assertEquals(theCommonName, theSignature.getSignerCommonName());
    }

}
