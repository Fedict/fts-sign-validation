package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.config.ThreadDataCleaner;
import com.bosa.signandvalidation.model.*;
import com.bosa.signingconfigurator.model.ProfileSignatureParameters;
import com.bosa.signingconfigurator.model.VisiblePdfSignatureParameters;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.bosa.signingconfigurator.exception.NullParameterException;
import com.bosa.signingconfigurator.exception.ProfileNotFoundException;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.pades.exception.ProtectedDocumentException;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.*;
import java.util.*;

import static com.bosa.signandvalidation.config.ErrorStrings.*;
import static com.bosa.signandvalidation.exceptions.Utils.*;

import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

import static org.springframework.http.HttpStatus.*;

@Service
public class SignService extends SignCommonService {
    protected final Logger logger = Logger.getLogger(SignService.class.getName());

    public DataToSignDTO getDataToSign(GetDataToSignDTO dataToSignDto) {
        try {
            checkAndRecordMDCToken(dataToSignDto.getToken());
            RemoteDocument toSignDocument = dataToSignDto.getToSignDocument();
            logger.info("Entering getDataToSign(File : " + toSignDocument.getName() + " - Size : " + toSignDocument.getBytes().length + ")");

            ClientSignatureParameters clientSigParams = dataToSignDto.getClientSignatureParameters();
            clientSigParams.setSigningDate(new Date());
            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(dataToSignDto.getSigningProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams);

            setOverrideRevocationStrategy(signProfile);

            checkCertificates(parameters);

            if (SignatureForm.PAdES.equals(signProfile.getSignatureForm())) {
                // Below is a Snyk false positive report : The "traversal" is in PdfVisibleSignatureService.getFont
                // or in "ImageIO.read" where it is NOT used as a path !
                prepareVisibleSignature(parameters, toSignDocument, clientSigParams);
            }

            ToBeSignedDTO dataToSign = altSignatureService.altGetDataToSign(toSignDocument, parameters, null, applicationName);

            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            byte [] bytesToSign = dataToSign.getBytes();
            if (signProfile.isReturnDigest()) bytesToSign = DSSUtils.digest(digestAlgorithm, bytesToSign);
            DataToSignDTO ret = new DataToSignDTO(digestAlgorithm, bytesToSign, dataToSignDto.getClientSignatureParameters().getSigningDate());
            logger.info("Returning from getDataToSign()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (PdfVisibleSignatureService.PdfVisibleSignatureException e) {
            logAndThrowEx(BAD_REQUEST, ERR_PDF_SIG_FIELD, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch(ProtectedDocumentException e) {
            logAndThrowEx(UNAUTHORIZED, NOT_ALLOWED_TO_SIGN, e.getMessage());
        } catch (AlertException e) {
            String message = e.getMessage();
            if (message == null || !message.startsWith("The new signature field position is outside the page dimensions!")) {
                logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
            }
            logger.warning(message);
            logAndThrowEx(INTERNAL_SERVER_ERROR, SIGNATURE_OUT_OF_BOUNDS, e);
        } catch (RuntimeException | IOException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    private void prepareVisibleSignature(RemoteSignatureParameters parameters, RemoteDocument pdf, ClientSignatureParameters clientSigParams) throws NullParameterException, IOException {
        VisiblePdfSignatureParameters pdfParams = clientSigParams.getPdfSigParams();
        if (pdfParams != null) {
            PDRectangle rect = null;
            String psfN = pdfParams.getPsfN();
            String psfC = pdfParams.getPsfC();
            if (psfN != null || psfC != null) {
                PDDocument pdfDoc = PDDocument.load(new ByteArrayInputStream(pdf.getBytes()), (String) null);
                rect = checkVisibleSignatureParameters(psfC, psfN, pdfParams.getPsp(), pdfDoc);
                pdfDoc.close();
            }
            pdfVisibleSignatureService.prepareVisibleSignature(parameters, rect == null ? 0 : rect.getHeight(), rect == null ? 0 : rect.getWidth(), clientSigParams);
        }
    }

    //*****************************************************************************************

    public DataToSignDTO getDataToSignMultiple(GetDataToSignMultipleDTO dataToSignDto) {
        try {
            checkAndRecordMDCToken(dataToSignDto.getToken());
            logger.info("Entering getDataToSignMultiple()");

            dataToSignDto.getClientSignatureParameters().setSigningDate(new Date());
            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(dataToSignDto.getSigningProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, dataToSignDto.getClientSignatureParameters());

            ToBeSignedDTO dataToSign = signatureServiceMultiple.getDataToSign(dataToSignDto.getToSignDocuments(), parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            byte [] bytesToSign = dataToSign.getBytes();
            if (signProfile.isReturnDigest()) bytesToSign = DSSUtils.digest(digestAlgorithm, bytesToSign);
            DataToSignDTO ret = new DataToSignDTO(digestAlgorithm, bytesToSign, dataToSignDto.getClientSignatureParameters().getSigningDate());
            logger.info("Returning from getDataToSignMultiple()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch(ProtectedDocumentException e) {
            logAndThrowEx(UNAUTHORIZED, NOT_ALLOWED_TO_SIGN, e.getMessage());
        } catch (RuntimeException | IOException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    @Async("asyncTasks")
    public CompletableFuture<Object> signDocumentASync(SignDocumentDTO signDto) {
        CompletableFuture<Object> task = new CompletableFuture<>();
        try {
            task.complete(signDocument(signDto));
        } catch(Exception e){
            task.completeExceptionally(e);
        } finally {
            // We're on a different thread (ASYNC) so clear all thread data
            ThreadDataCleaner.clearAll();
        }
        return task;
    }

    //*****************************************************************************************

    public RemoteDocument signDocument(SignDocumentDTO signDocumentDto) {
        try {
            checkAndRecordMDCToken(signDocumentDto.getToken());
            RemoteDocument toSignDocument = signDocumentDto.getToSignDocument();
            logger.info("Entering signDocument(File : " + toSignDocument.getName() + " - Size : " + toSignDocument.getBytes().length + ")");

            ClientSignatureParameters clientSigParams = signDocumentDto.getClientSignatureParameters();
            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(signDocumentDto.getSigningProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams);
            setOverrideRevocationStrategy(signProfile);

            if (SignatureForm.PAdES.equals(signProfile.getSignatureForm())) {
                // Below is a Snyk false positive report : The "traversal" is in PdfVisibleSignatureService.getFont
                // or in "ImageIO.read" where it is NOT used as a path !
                prepareVisibleSignature(parameters, toSignDocument, clientSigParams);
            }

            SignatureValueDTO signatureValueDto = getSignatureValueDTO(parameters, signDocumentDto.getSignatureValue());
            RemoteDocument signedDoc = altSignatureService.altSignDocument(toSignDocument, parameters, signatureValueDto, null, applicationName);

            // Adding the source document as detacheddocuments is needed when using a "DETACHED" sign profile,
            // as it happens that "ATTACHED" profiles don't bother the detacheddocuments parameters we're adding them at all times
            List<RemoteDocument> detachedDocuments = clientSigParams.getDetachedContents();
            if (detachedDocuments == null) detachedDocuments = new ArrayList<>();
            detachedDocuments.add(signDocumentDto.getToSignDocument());

//            try (FileOutputStream fos = new FileOutputStream("signed.file")) { fos.write(signedDoc.getBytes()); }

            RemoteDocument ret =  validateResult(signedDoc, detachedDocuments, parameters, null, null, signDocumentDto.getValidatePolicy(), signProfile);
            logger.info("Returning from signDocument()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException | IOException e) {
            handleRevokedCertificates(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    @Async("asyncTasks")
    public CompletableFuture<Object> signDocumentMultipleASync(SignDocumentMultipleDTO signDto) {
        CompletableFuture<Object> task = new CompletableFuture<>();
        try {
            task.complete(signDocumentMultiple(signDto));
        } catch(Exception e){
            task.completeExceptionally(e);
        } finally {
            // We're on a different thread (ASYNC) so clear all thread data
            ThreadDataCleaner.clearAll();
        }
        return task;
    }

    //*****************************************************************************************

    public RemoteDocument signDocumentMultiple(SignDocumentMultipleDTO signDto) {
        try {
            checkAndRecordMDCToken(signDto.getToken());
            logger.info("Entering signDocumentMultiple()");

            ClientSignatureParameters clientSigParams = signDto.getClientSignatureParameters();
            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(signDto.getSigningProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams);
            setOverrideRevocationStrategy(signProfile);

            SignatureValueDTO signatureValueDto = getSignatureValueDTO(parameters, signDto.getSignatureValue());
            RemoteDocument signedDoc = signatureServiceMultiple.signDocument(signDto.getToSignDocuments(), parameters, signatureValueDto);

            //try (FileOutputStream fos = new FileOutputStream("signed.file.xml")) { fos.write(signedDoc.getBytes()); }

            // Adding the source document as detacheddocuments is needed when using a "DETACHED" sign profile,
            // as it happens that "ATTACHED" profiles don't bother the detacheddocuments parameters we're adding them at all times
            RemoteDocument ret = validateResult(signedDoc, signDto.getToSignDocuments(), parameters, null, null, signDto.getValidatePolicy(), signProfile);
            logger.info("Returning from signDocumentMultiple()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException | IOException e) {
            handleRevokedCertificates(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    @Async("asyncTasks")
    public CompletableFuture<Object> extendDocumentMultipleASync(ExtendDocumentDTO extendDocumentDto) {
        CompletableFuture<Object> task = new CompletableFuture<>();
        try {
            task.complete(extendDocumentMultiple(extendDocumentDto));
        } catch(Exception e){
            task.completeExceptionally(e);
        } finally {
            // We're on a different thread (ASYNC) so clear all thread data
            ThreadDataCleaner.clearAll();
        }
        return task;
    }

    //*****************************************************************************************

    public RemoteDocument extendDocumentMultiple(ExtendDocumentDTO extendDocumentDto) {
        try {
            checkAndRecordMDCToken(extendDocumentDto.getToken());
            logger.info("Entering extendDocumentMultiple()");

            ProfileSignatureParameters extendProfile = signingConfigService.findProfileParamsById(extendDocumentDto.getExtendProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getExtensionParams(extendProfile, extendDocumentDto.getDetachedContents());
            setOverrideRevocationStrategy(extendProfile);

            RemoteDocument extendedDoc = signatureServiceMultiple.extendDocument(extendDocumentDto.getToExtendDocument(), parameters);

            RemoteDocument ret = validateResult(extendedDoc, extendDocumentDto.getDetachedContents(), parameters, null, null, null, extendProfile);
            logger.info("Returning from extendDocumentMultiple()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException | IOException e) {
            handleRevokedCertificates(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    @Async("asyncTasks")
    public CompletableFuture<Object> extendDocumentASync(ExtendDocumentDTO extendDocumentDto) {
        CompletableFuture<Object> task = new CompletableFuture<>();
        try {
            task.complete(extendDocument(extendDocumentDto));
        } catch(Exception e){
            task.completeExceptionally(e);
        } finally {
            // We're on a different thread (ASYNC) so clear all thread data
            ThreadDataCleaner.clearAll();
        }
        return task;
    }

    //*****************************************************************************************

    public RemoteDocument extendDocument(ExtendDocumentDTO extendDocumentDto) {
        try {
            checkAndRecordMDCToken(extendDocumentDto.getToken());
            logger.info("Entering extendDocument()");

            ProfileSignatureParameters extendProfile = signingConfigService.findProfileParamsById(extendDocumentDto.getExtendProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getExtensionParams(extendProfile, extendDocumentDto.getDetachedContents());
            setOverrideRevocationStrategy(extendProfile);

            RemoteDocument extendedDoc = altSignatureService.extendDocument(extendDocumentDto.getToExtendDocument(), parameters);

            RemoteDocument ret = validateResult(extendedDoc, extendDocumentDto.getDetachedContents(), parameters, null, null, null, extendProfile);
            logger.info("Returning from extendDocument()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException | IOException e) {
            handleRevokedCertificates(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    public RemoteDocument timestampDocument(TimestampDocumentDTO timestampDocumentDto) {
        try {
            checkAndRecordMDCToken(timestampDocumentDto.getToken());
            logger.info("Entering timestampDocument()");

            RemoteTimestampParameters parameters = signingConfigService.getTimestampParams(timestampDocumentDto.getProfileId());

            RemoteDocument ret = altSignatureService.timestamp(timestampDocumentDto.getDocument(), parameters);
            logger.info("Returning from timestampDocument()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    public RemoteDocument timestampDocumentMultiple(TimestampDocumentMultipleDTO timestampDocumentDto) {
        try {
            checkAndRecordMDCToken(timestampDocumentDto.getToken());
            logger.info("Entering timestampDocumentMultiple()");

            RemoteTimestampParameters parameters = signingConfigService.getTimestampParams(timestampDocumentDto.getProfileId());

            RemoteDocument ret = signatureServiceMultiple.timestamp(timestampDocumentDto.getDocuments(), parameters);
            logger.info("Returning from timestampDocumentMultiple()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    public DataToSignDTO getDataToSignXades(GetDataToSignXMLElementsDTO getDataToSignDto) {
        try {
            checkAndRecordMDCToken(getDataToSignDto.getToken());
            logger.info("Entering getDataToSignXades()");

            ClientSignatureParameters clientSigParams = getDataToSignDto.getClientSignatureParameters();
            Date signingDate = new Date();
            clientSigParams.setSigningDate(signingDate);

            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(getDataToSignDto.getSigningProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams);

            List<DSSReference> references = buildReferences(signingDate, getDataToSignDto.getElementIdsToSign(), parameters.getReferenceDigestAlgorithm());

            ToBeSignedDTO dataToSign = altSignatureService.altGetDataToSign(getDataToSignDto.getToSignDocument(), parameters, references, null);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            DataToSignDTO ret = new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()), signingDate);
            logger.info("Returning from getDataToSignXades()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (PdfVisibleSignatureService.PdfVisibleSignatureException e) {
            logAndThrowEx(BAD_REQUEST, ERR_PDF_SIG_FIELD, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch(ProtectedDocumentException e) {
            logAndThrowEx(UNAUTHORIZED, NOT_ALLOWED_TO_SIGN, e.getMessage());
        } catch (RuntimeException | IOException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    public RemoteDocument signDocumentXades(SignXMLElementsDTO signDto) {
        try {
            checkAndRecordMDCToken(signDto.getToken());
            logger.info("Entering signDocumentXades()");

            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(signDto.getSigningProfileId());
            ClientSignatureParameters clientSigParams = signDto.getClientSignatureParameters();
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams);
            setOverrideRevocationStrategy(signProfile);

            SignatureValueDTO signatureValueDto = getSignatureValueDTO(parameters, signDto.getSignatureValue());
            List<DSSReference> references = buildReferences(clientSigParams.getSigningDate(), signDto.getElementIdsToSign(), parameters.getReferenceDigestAlgorithm());
            RemoteDocument signedDoc = altSignatureService.altSignDocument(signDto.getToSignDocument(), parameters, signatureValueDto, references, null);

            signedDoc.setName(signDto.getToSignDocument().getName());
            logger.info("Returning from signDocumentXades()");
            return signedDoc;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (PdfVisibleSignatureService.PdfVisibleSignatureException e) {
            logAndThrowEx(BAD_REQUEST, ERR_PDF_SIG_FIELD, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException | IOException e) {
            handleRevokedCertificates(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************
}
