package com.zetes.projects.bosa.signandvalidation.service;

import java.util.List;
import java.io.Serializable;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.common.RemoteDocumentValidationService;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlToken;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;

/**
 * This validation service calls the DSS validation service and then applies some extra checks.
 */
public class BosaRemoteDocumentValidationService {
	private RemoteDocumentValidationService remoteDocumentValidationService;

	public BosaRemoteDocumentValidationService() {
	}

	public void setRemoteDocumentValidationService(RemoteDocumentValidationService remoteDocumentValidationService) {
		this.remoteDocumentValidationService = remoteDocumentValidationService;
	}

	public WSReportsDTO validateDocument(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments, RemoteDocument policy) {

		// Let DSS to it's normal validation
		WSReportsDTO report = remoteDocumentValidationService.validateDocument(signedDocument, originalDocuments, policy);

		// Check if the signature algo is MD5 or SHA1
		XmlDiagnosticData diagsData = report.getDiagnosticData();
		List<eu.europa.esig.dss.diagnostic.jaxb.XmlSignature> signatures = diagsData.getSignatures();
		int sigCount = signatures.size();
		for (int i = 0; i < sigCount; i++) {
			eu.europa.esig.dss.diagnostic.jaxb.XmlSignature sig = signatures.get(i);
			XmlBasicSignature basicSig = sig.getBasicSignature();
			DigestAlgorithm digestAlgo = basicSig.getDigestAlgoUsedToSignThisToken();
			String dAlgo = digestAlgo.toString();
			if ("SHA1".equals(dAlgo) || "MD5".equals(dAlgo)) {

				// Modify the simple report
				XmlSimpleReport simpleReport = report.getSimpleReport();
				List<XmlToken> tokens = simpleReport.getSignatureOrTimestamp();
				XmlToken token = tokens.get(i);
				if (!Indication.TOTAL_FAILED.equals(token.getIndication())) {
					token.setIndication(Indication.TOTAL_FAILED);
					token.setSubIndication(SubIndication.CRYPTO_CONSTRAINTS_FAILURE);
					token.getErrors().add(digestAlgo + " signatures not allowed");
					int validSigsCount = simpleReport.getValidSignaturesCount();
					if (validSigsCount > 0)
						simpleReport.setValidSignaturesCount(validSigsCount - 1);
				}

				// Modify the detailed report
				XmlDetailedReport detailedReport = report.getDetailedReport();
				List<Serializable> sigs = detailedReport.getSignatureOrTimestampOrCertificate();
				int sigsCount = sigs.size();
				eu.europa.esig.dss.detailedreport.jaxb.XmlSignature signat =
					(eu.europa.esig.dss.detailedreport.jaxb.XmlSignature) sigs.get(i);
				XmlValidationProcessBasicSignature validation = signat.getValidationProcessBasicSignature();
				XmlConclusion conclusion = validation.getConclusion();
				conclusion.setIndication(Indication.TOTAL_FAILED);
				conclusion.setSubIndication(SubIndication.CRYPTO_CONSTRAINTS_FAILURE);
				XmlName err = new XmlName();
				err.setNameId("err");
				err.setValue(digestAlgo + " signatures not allowed");
				conclusion.getErrors().add(err);
			}
		}

		return report;
	}
}
