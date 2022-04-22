package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.SignatureIndicationsDTO;
import eu.europa.esig.dss.simplereport.jaxb.*;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static com.bosa.signandvalidation.config.ErrorStrings.CERT_REVOKED;
import static eu.europa.esig.dss.enumerations.Indication.*;
import static eu.europa.esig.dss.enumerations.SubIndication.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class ReportServiceTest {

    private static ReportsService srv = new ReportsService();
    private static Date now = new Date();
    private static Date past = new Date(now.getTime() - 10000);

    @Test
    public void getSignatureIndicationsDtoNoSignatureTest() throws Exception {
        WSReportsDTO report = new WSReportsDTO();
        XmlSimpleReport simple = new XmlSimpleReport();
        report.setSimpleReport(simple);
        simple.setSignaturesCount(0);
        SignatureIndicationsDTO dto = srv.getLatestSignatureIndicationsDto(report, past);

        assertEquals(INDETERMINATE, dto.getIndication());
        assertEquals(SIGNED_DATA_NOT_FOUND.name(), dto.getSubIndicationLabel());
    }

    @Test
    public void getSignatureIndicationsDtoOneSignatureTest() throws Exception {
        WSReportsDTO report = new WSReportsDTO();
        XmlSimpleReport simple = new XmlSimpleReport();
        report.setSimpleReport(simple);
        simple.setSignaturesCount(1);
        List<XmlToken> signatures = simple.getSignatureOrTimestamp();
        XmlSignature signature = new XmlSignature();
        signature.setBestSignatureTime(now);
        signature.setIndication(TOTAL_PASSED);
        signatures.add(signature);
        SignatureIndicationsDTO dto = srv.getLatestSignatureIndicationsDto(report, past);

        assertEquals(TOTAL_PASSED, dto.getIndication());
    }

    @Test
    public void getSignatureIndicationsDtoOnePassedSignatureTest() throws Exception {
        WSReportsDTO report = new WSReportsDTO();
        XmlSimpleReport simple = new XmlSimpleReport();
        report.setSimpleReport(simple);
        simple.setSignaturesCount(1);
        List<XmlToken> signatures = simple.getSignatureOrTimestamp();
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
        WSReportsDTO report = new WSReportsDTO();
        XmlSimpleReport simple = new XmlSimpleReport();
        report.setSimpleReport(simple);
        simple.setSignaturesCount(1);
        List<XmlToken> signatures = simple.getSignatureOrTimestamp();
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
        WSReportsDTO report = new WSReportsDTO();
        XmlSimpleReport simple = new XmlSimpleReport();
        report.setSimpleReport(simple);
        simple.setSignaturesCount(1);
        List<XmlToken> signatures = simple.getSignatureOrTimestamp();
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
        WSReportsDTO report = new WSReportsDTO();
        XmlSimpleReport simple = new XmlSimpleReport();
        report.setSimpleReport(simple);
        simple.setSignaturesCount(1);
        List<XmlToken> signatures = simple.getSignatureOrTimestamp();
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
        WSReportsDTO report = new WSReportsDTO();
        XmlSimpleReport simple = new XmlSimpleReport();
        report.setSimpleReport(simple);
        simple.setSignaturesCount(2);
        List<XmlToken> signatures = simple.getSignatureOrTimestamp();
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
}
