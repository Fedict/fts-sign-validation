package com.bosa.signandvalidation.service;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.io.Serializable;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDistinguishedName;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.simplereport.jaxb.*;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;

/**
 * This validation service calls the DSS validation service and then applies some extra checks.
 */
public class BosaRemoteDocumentValidationService {
	private static final String BRCA_3_CONSTRAINT_FILE = "BRCA3_constraint.xml";
	private ShadowRemoteDocumentValidationService remoteDocumentValidationService;

	public BosaRemoteDocumentValidationService() {
	}

	public void setRemoteDocumentValidationService(ShadowRemoteDocumentValidationService remoteDocumentValidationService) {
		this.remoteDocumentValidationService = remoteDocumentValidationService;
	}

	public WSReportsDTO validateDocument(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments, RemoteDocument policy) {
		return validateDocument(signedDocument, originalDocuments, policy, null);
	}

	public WSReportsDTO validateDocument(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments, RemoteDocument policy, RemoteSignatureParameters parameters) {

		// Let DSS do its normal validation
		WSReportsDTO report = remoteDocumentValidationService.validateDocument(new DataToValidateDTO(signedDocument, originalDocuments, policy));
		if (policy == null && hasBRCA3RevocationFreshnessError(report)) {
			try {
				InputStream brca3is = BosaRemoteDocumentValidationService.class.getResourceAsStream("/policy/" + BRCA_3_CONSTRAINT_FILE);
				RemoteDocument brca3Policy = new RemoteDocument(Utils.toByteArray(brca3is), BRCA_3_CONSTRAINT_FILE);
				report = remoteDocumentValidationService.validateDocument(new DataToValidateDTO(signedDocument, originalDocuments, brca3Policy));
			} catch (IOException e) {
				throw new RuntimeException(BRCA_3_CONSTRAINT_FILE + " not found");
			}
		}

		// When some back end servers (don't know which ones...) are down seems DSS can produce a signature that does not reflect the
		// requested "parameters.getSignatureLevel()". For example even though an LTA was requested the result is not LTA.
		// The code below is there to double-check this, it also makes sure SHA1 & MD5 are never used
		XmlDiagnosticData diagsData = report.getDiagnosticData();
		List<XmlSignature> signatures = diagsData.getSignatures();
		int sigCount = signatures.size();
		XmlSignature maxSig = null;
		for (int i = 0; i < sigCount; i++) {
			XmlSignature sig = signatures.get(i);
			// Check if the signature algo is MD5 or SHA1 and make it an error
			XmlBasicSignature basicSig = sig.getBasicSignature();
			DigestAlgorithm digestAlgo = basicSig.getDigestAlgoUsedToSignThisToken();
			if (digestAlgo != null) {
				String dAlgo = digestAlgo.toString();
				if ("SHA1".equals(dAlgo) || "MD5".equals(dAlgo)) {
					modifyReports(report, sig.getId(), SubIndication.CRYPTO_CONSTRAINTS_FAILURE,
							digestAlgo + " signatures not allowed");
				}
			}

			// Identify the latest signature (for next step)
			// Though this could not be the signature we "just made".
			// It would be better to identify the signature based on the signed digest but this one is still better than the previous one using the 10 seconds delay
			if (maxSig == null || sig.getClaimedSigningTime().after(maxSig.getClaimedSigningTime())) {
				maxSig = sig;
			}
		}

		if (parameters != null && maxSig != null) {
			// Check if the signature level (of the sig we just made) corresponds with the requested level
			SignatureLevel expSigLevel = parameters.getSignatureLevel();
			SignatureLevel sigLevel = maxSig.getSignatureFormat();
			if (!sigLevel.equals(expSigLevel)) {
				modifyReports(report, maxSig.getId(), SubIndication.FORMAT_FAILURE, "expected level " + expSigLevel + " but was: " + sigLevel);
			}
		}

		return report;
	}

	private static boolean hasBRCA3RevocationFreshnessError(WSReportsDTO report) {
		for(XmlToken sigOrTS : report.getSimpleReport().getSignatureOrTimestamp()) {
			if (sigOrTS instanceof eu.europa.esig.dss.simplereport.jaxb.XmlSignature &&
					Indication.INDETERMINATE.equals(sigOrTS.getIndication()) &&
					SubIndication.TRY_LATER.equals(sigOrTS.getSubIndication())) {
				XmlCertificateChain certChain = sigOrTS.getCertificateChain();
				if (certChain == null) continue;
				List<XmlCertificate> certChain2 = certChain.getCertificate();
				XmlCertificate rootCert = certChain2.get(certChain2.size() - 1);
				if (isBRCA3Cert(report.getDiagnosticData().getUsedCertificates(), rootCert.getId())) return true;
			}
		}
	return false;
	}

	private static boolean isBRCA3Cert(List<eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate> certs, String id) {
		for (eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate cert : certs) {
			if (id.equals(cert.getId())) {
				for(XmlDistinguishedName formattedDn : cert.getSubjectDistinguishedName()) {
					if ("CANONICAL".equals(formattedDn.getFormat()) && "cn=belgium root ca3,c=be".equals(formattedDn.getValue())) return true;
				}
			}
		}
		return false;
	}

	private void modifyReports(WSReportsDTO report, String sigId, SubIndication subIndication, String errMesg) {
		// Modify the simple report
		XmlSimpleReport simpleReport = report.getSimpleReport();
		for (XmlToken token : simpleReport.getSignatureOrTimestamp()) {
			if (token.getId().equals(sigId)) {
				if (!Indication.TOTAL_FAILED.equals(token.getIndication())) {
					token.setIndication(Indication.TOTAL_FAILED);
					token.setSubIndication(subIndication);
					// DSS 5.8 had an "errors" field.
					// DSS 5.9 has AdESValidationDetails and QualificationDetails
					//			each have 3 lists of key/value pairs "error", "warning" and "info"
					// We're using the "error" list to add the error.
					XmlDetails adesValidationDetails = token.getAdESValidationDetails();
					if (adesValidationDetails == null) token.setAdESValidationDetails(adesValidationDetails = new XmlDetails());
					XmlMessage error = new XmlMessage();
					error.setKey("err");
					error.setValue(errMesg);
					adesValidationDetails.getError().add(error);
					int validSigsCount = simpleReport.getValidSignaturesCount();
					if (validSigsCount > 0)
						simpleReport.setValidSignaturesCount(validSigsCount - 1);
				}
				break;
			}
		}
		// Modify the detailed report
		for (Serializable sigTsOrCert : report.getDetailedReport().getSignatureOrTimestampOrCertificate()) {
			eu.europa.esig.dss.detailedreport.jaxb.XmlSignature signat = (eu.europa.esig.dss.detailedreport.jaxb.XmlSignature)sigTsOrCert;
			if (signat.getId().equals(sigId)) {
				XmlValidationProcessBasicSignature validation = signat.getValidationProcessBasicSignature();
				XmlConclusion conclusion = validation.getConclusion();
				conclusion.setIndication(Indication.TOTAL_FAILED);
				conclusion.setSubIndication(subIndication);

				eu.europa.esig.dss.detailedreport.jaxb.XmlMessage err = new eu.europa.esig.dss.detailedreport.jaxb.XmlMessage();
				err.setKey("err");
				err.setValue(errMesg);
				conclusion.getErrors().add(err);
				break;
			}
		}
	}
}
