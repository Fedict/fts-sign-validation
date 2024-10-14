package com.bosa.signandvalidation.service;

/******************************* WARNING ****************************

 This class is a shadow of the DSS 5.13 "RemoteDocumentValidationService"
 It is needed because there is an issue when validating Xades signatures
 with "Policies". The code was using a non-proxied "dataLoader" object
 which is blocked by firewalls.
 Since there was no way to inject the fileCacheDataLoader into the object
 chain I (chmo) duplicated the DSS class and modified it to allow the
 injection of the fileCacheDataLoader at object creation and set the
 dataloader on the signaturePolicyProvider

*********************************************************************/


/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.exception.DSSRemoteServiceException;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.List;

/**
 * The remote validation service
 */
public class ShadowRemoteDocumentValidationService {

    private static final Logger LOG = LoggerFactory.getLogger(ShadowRemoteDocumentValidationService.class);

    /** The certificate verifier to use */
    private CertificateVerifier verifier;

    /**************** fileCacheDataLoader will land here */
    private DataLoader dataLoader;


    /** The validation policy to be used by default */
    private ValidationPolicy defaultValidationPolicy;
    /**
     * Default construction instantiating object with null certificate verifier
     */
    public ShadowRemoteDocumentValidationService() {
        // empty
    }

    /**************** fileCacheDataLoader setter */
    public void setDataLoader(DataLoader dataLoader) {
        this.dataLoader = dataLoader;
    }

    /**
     * Sets the certificate verifier
     *
     * @param verifier {@link CertificateVerifier}
     */
    public void setVerifier(CertificateVerifier verifier) {
        this.verifier = verifier;
    }

    /**
     * Sets the validation policy to be used by default, when no policy provided within the request
     *
     * @param validationPolicy {@link InputStream}
     */
    public void setDefaultValidationPolicy(InputStream validationPolicy) {
        try {
            this.defaultValidationPolicy = ValidationPolicyFacade.newFacade().getValidationPolicy(validationPolicy);
        } catch (Exception e) {
            throw new DSSRemoteServiceException(String.format("Unable to instantiate validation policy: %s", e.getMessage()), e);
        }
    }

    /**
     * Sets the validation policy to be used by default, when no policy provided within the request
     *
     * @param validationPolicy {@link ValidationPolicy}
     */
    public void setDefaultValidationPolicy(ValidationPolicy validationPolicy) {
        this.defaultValidationPolicy = validationPolicy;
    }

    /**
     * Validates the document
     *
     * @param dataToValidate {@link DataToValidateDTO} the request
     * @return {@link WSReportsDTO} response
     */
    public WSReportsDTO validateDocument(DataToValidateDTO dataToValidate, boolean skipPDFVisualComparison) {
        LOG.info("ValidateDocument in process...");
        SignedDocumentValidator validator = initValidator(dataToValidate, skipPDFVisualComparison);

        Reports reports;
        RemoteDocument policy = dataToValidate.getPolicy();
        if (policy != null) {
            reports = validator.validateDocument(getValidationPolicy(policy));
        } else if (defaultValidationPolicy != null) {
            reports = validator.validateDocument(defaultValidationPolicy);
        } else {
            reports = validator.validateDocument();
        }

        WSReportsDTO reportsDTO = new WSReportsDTO(reports.getDiagnosticDataJaxb(), reports.getSimpleReportJaxb(),
                reports.getDetailedReportJaxb(), reports.getEtsiValidationReportJaxb());
        LOG.info("ValidateDocument is finished");
        return reportsDTO;
    }

    /**
     * Gets the original documents
     *
     * @param dataToValidate {@link DataToValidateDTO} request
     * @return a list of {@link RemoteDocument}s
     */
    public List<RemoteDocument> getOriginalDocuments(DataToValidateDTO dataToValidate) {
        LOG.info("GetOriginalDocuments in process...");
        SignedDocumentValidator validator = initValidator(dataToValidate, false);

        String signatureId = dataToValidate.getSignatureId();
        if (signatureId == null) {
            List<AdvancedSignature> signatures = validator.getSignatures();
            if (!signatures.isEmpty()) {
                LOG.debug("SignatureId is not defined, the first signature is used");
                signatureId = signatures.get(0).getId();
            }
        }

        List<DSSDocument> originalDocuments = validator.getOriginalDocuments(signatureId);
        List<RemoteDocument> remoteDocuments = RemoteDocumentConverter.toRemoteDocuments(originalDocuments);
        LOG.info("GetOriginalDocuments is finished");
        return remoteDocuments;
    }

    private ValidationPolicy getValidationPolicy(RemoteDocument policy) {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(policy.getBytes())) {
            return ValidationPolicyFacade.newFacade().getValidationPolicy(bais);
        } catch (Exception e) {
            throw new IllegalInputException(String.format("Unable to load the validation policy : %s", e.getMessage()), e);
        }
    }

    /**
     * Instantiates a {@code SignedDocumentValidator} based on the request data DTO
     *
     * @param dataToValidate          {@link DataToValidateDTO} representing the request data
     * @param skipPDFVisualComparison   When true, skip Validation "PDF Visual checks". Those are extremely slow an
     *                                 not needed with a validation coming right after a new signature was made
     * @return {@link SignedDocumentValidator}
     */
    protected SignedDocumentValidator initValidator(DataToValidateDTO dataToValidate, boolean skipPDFVisualComparison) {
        DSSDocument signedDocument = RemoteDocumentConverter.toDSSDocument(dataToValidate.getSignedDocument());
        SignedDocumentValidator signedDocValidator = SignedDocumentValidator.fromDocument(signedDocument);

        // Improve validation performance by disabling the visual PDF checks
        if (skipPDFVisualComparison && signedDocValidator instanceof PDFDocumentValidator) {
            IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();
            DefaultPdfDifferencesFinder pdfDifferencesFinder = new DefaultPdfDifferencesFinder();
            pdfDifferencesFinder.setMaximalPagesAmountForVisualComparison(0);       // '0' => skip the visual comparison
            pdfObjFactory.setPdfDifferencesFinder(pdfDifferencesFinder);
            DefaultPdfObjectModificationsFinder pdfObjectModificationsFinder = new DefaultPdfObjectModificationsFinder();
            pdfObjectModificationsFinder.setMaximumObjectVerificationDeepness(0);   // '0' => skip the visual comparison
            pdfObjFactory.setPdfObjectModificationsFinder(pdfObjectModificationsFinder);
            ((PDFDocumentValidator)signedDocValidator).setPdfObjFactory(pdfObjFactory);
        }

        if (Utils.isCollectionNotEmpty(dataToValidate.getOriginalDocuments())) {
            signedDocValidator.setDetachedContents(RemoteDocumentConverter.toDSSDocuments(dataToValidate.getOriginalDocuments()));
        }
        if (Utils.isCollectionNotEmpty(dataToValidate.getEvidenceRecords())) {
            signedDocValidator.setDetachedEvidenceRecordDocuments(RemoteDocumentConverter.toDSSDocuments(dataToValidate.getEvidenceRecords()));
        }
        signedDocValidator.setCertificateVerifier(verifier);
        // If null, uses default (NONE)
        if (dataToValidate.getTokenExtractionStrategy() != null) {
            signedDocValidator.setTokenExtractionStrategy(dataToValidate.getTokenExtractionStrategy());
        }

        /**************** Inject fileCacheDataLoader in SignaturePolicyProvider */
        SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
        signaturePolicyProvider.setDataLoader(dataLoader);
        signedDocValidator.setSignaturePolicyProvider(signaturePolicyProvider);

        return signedDocValidator;
    }
}
