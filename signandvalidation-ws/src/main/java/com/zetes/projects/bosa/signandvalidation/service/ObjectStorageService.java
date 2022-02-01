/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zetes.projects.bosa.signandvalidation.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.zetes.projects.bosa.signandvalidation.TokenParser;
import com.zetes.projects.bosa.signandvalidation.model.AllowedToSign;
import com.zetes.projects.bosa.signandvalidation.model.DocumentMetadataDTO;
import com.zetes.projects.bosa.signandvalidation.model.GetTokenForDocumentDTO;
import com.zetes.projects.bosa.signandvalidation.model.StoredKey;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import io.minio.BucketExistsArgs;
import io.minio.GetObjectArgs;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import io.minio.errors.ErrorResponseException;
import io.minio.errors.InsufficientDataException;
import io.minio.errors.InternalException;
import io.minio.errors.InvalidResponseException;
import io.minio.errors.ServerException;
import io.minio.errors.XmlParserException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.activation.MimetypesFileTypeMap;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 *
 * @author wouter
 */
@Service
public class ObjectStorageService {
    @Value("${objectstorage.endpoint}")
    private String S3Endpoint;
    
    @Value("${objectstorage.accesskey}")
    private String accessKey;
    
    @Value("${objectstorage.secretkey}")
    private String secretKey;
    
    @Value("${objectstorage.secretbucket}")
    private String secretBucket;
    
    private final Map<String, StoredKey> keys;

    private StoredKey defaultKey = null;
    private final MimetypesFileTypeMap mimeMap;
    
    private MinioClient client;
    private MinioClient getClient() {
        if(client == null) {
            client = MinioClient.builder()
                    .endpoint(S3Endpoint)
                    .credentials(accessKey, secretKey)
                    .build();
        }
        return client;
    }
    
    private String getKid() throws InvalidKeyConfigException {
        try {
            if(defaultKey == null || defaultKey.isTooOld()) {
                StoredKey k = new StoredKey();
                ObjectMapper om = new ObjectMapper();
                byte[] json = om.writeValueAsBytes(k);
                getClient().putObject(PutObjectArgs.builder()
                        .bucket(secretBucket)
                        .object("keys/" + k.getKid() + ".json")
                        .stream(new ByteArrayInputStream(json), json.length, -1)
                        .build()
                );
                defaultKey = k;
                keys.put(defaultKey.getKid(), defaultKey);
            }
            return defaultKey.getKid();
        } catch (NoSuchAlgorithmException | ErrorResponseException
                | InsufficientDataException | InternalException
                | InvalidKeyException | InvalidResponseException
                | IOException | ServerException | XmlParserException ex) {
            Logger.getLogger(ObjectStorageService.class.getName()).log(Level.SEVERE, null, ex);
            throw new InvalidKeyConfigException();
        }
    }
    
    public ObjectStorageService() {
        keys = new HashMap<>();
        mimeMap = new MimetypesFileTypeMap();
        mimeMap.addMimeTypes("application/pdf PDF pdf");
        mimeMap.addMimeTypes("application/xml xml XML docx");
        mimeMap.addMimeTypes("aplication/xslt+xml xslt XSLT");
    }

    public SecretKey getKeyForId(String kid) throws InvalidKeyConfigException {
        try {
            if(defaultKey != null && defaultKey.getKid().equals(kid)) {
                return defaultKey.getData();
            }
            if(!keys.containsKey(kid)) {
                InputStream stream = getClient().getObject(GetObjectArgs.builder()
                        .bucket(secretBucket)
                        .object("keys/" + kid + ".json")
                        .build()
                );
                ObjectMapper om = new ObjectMapper();
                StoredKey k = om.readValue(stream, StoredKey.class);
                if(k.getKid() == null || !k.getKid().equals(kid)) {
                    throw new InvalidKeyConfigException();
                }
                keys.put(kid, k);
            }
            return keys.get(kid).getData();
        } catch (ErrorResponseException | InsufficientDataException
                | InternalException | InvalidKeyException
                | InvalidResponseException | IOException
                | NoSuchAlgorithmException | ServerException
                | XmlParserException ex) {
            Logger.getLogger(ObjectStorageService.class.getName()).log(Level.SEVERE, null, ex);
            throw new InvalidKeyConfigException();
        }
    }
    public String getProfileForToken(TokenParser token) {
        return token.getProf();
    }
    public String getProfileForToken(String token) throws JOSEException, ParseException, InvalidKeyConfigException {
        return new TokenParser(token, this).getProf();
    }
    public boolean isValidAuth(String accesskey, String secretkey) {
        try {
            MinioClient testClient = MinioClient.builder()
                    .endpoint(S3Endpoint)
                    .credentials(accesskey, secretkey)
                    .build();
            return testClient.bucketExists(BucketExistsArgs.builder().bucket(accesskey).build());
        } catch (ErrorResponseException | InsufficientDataException
                | InternalException | InvalidKeyException
                | InvalidResponseException | IOException
                | NoSuchAlgorithmException | ServerException
                | XmlParserException ex) {
            Logger.getLogger(ObjectStorageService.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }
    }

    public String getTokenForDocument(GetTokenForDocumentDTO tokenData) throws TokenCreationFailureException, InvalidKeyConfigException {
        try {
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                    .claim("cid", tokenData.getName())
                    .claim("in", tokenData.getIn())
                    .claim("out", tokenData.getOut())
                    .claim("prof", tokenData.getProf())
                    .claim("nd", tokenData.getNoDownload())
                    .issueTime(new Date());

            if (tokenData.getXslt() != null) builder.claim("xslt", tokenData.getXslt());
            if (tokenData.getPsp() != null) builder.claim("psp", tokenData.getPsp());
            if (tokenData.getPsfN() != null) builder.claim("psfN", tokenData.getPsfN());
            if (tokenData.getPsfC() != null) builder.claim("psfC", tokenData.getPsfC());
            if (tokenData.getPsfP() != null) builder.claim("psfP", tokenData.getPsfP());
            if (tokenData.getLang() != null) builder.claim("lang", tokenData.getLang());
            if (tokenData.getSignTimeout() != null) builder.claim("st", tokenData.getSignTimeout());
            if (tokenData.getRequestDocumentReadConfirm() != null) builder.claim("rdrc", tokenData.getRequestDocumentReadConfirm());
            if (tokenData.getPolicyId() != null) builder.claim("polId", tokenData.getPolicyId());
            if (tokenData.getPolicyDescription() != null) builder.claim("polDesc", tokenData.getPolicyDescription());
            if (tokenData.getPolicyDigestAlgorithm() != null) builder.claim("polDigAlg", tokenData.getPolicyDigestAlgorithm());
            if (tokenData.getAllowedToSign() != null) {
                List<String> nnList = new LinkedList<String>();
                for (AllowedToSign allowedToSignItem : tokenData.getAllowedToSign()) {
                    nnList.add(allowedToSignItem.getNN());
                }
                builder.claim("allowedToSign", nnList);
            }

            PlainJWT jwt = new PlainJWT(builder.build());
            JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                    .keyID(getKid())
                    .build(), new Payload(jwt.serialize()));
            jweObject.encrypt(new DirectEncrypter(getKeyForId(getKid())));
            return jweObject.serialize();
        } catch (JOSEException ex) {
            Logger.getLogger(ObjectStorageService.class.getName()).log(Level.SEVERE, null, ex);
            throw new TokenCreationFailureException();
        } catch (IllegalArgumentException ex) {
            Logger.getLogger(ObjectStorageService.class.getName()).log(Level.SEVERE, null, ex);
            throw new TokenCreationFailureException();
        }
    }
    public byte[] getFileForToken(String dataName, String cid) throws InvalidTokenException {
        try {
            InputStream stream = getClient().getObject(
                    GetObjectArgs.builder()
                            .bucket(cid)
                            .object(dataName)
                            .build()
            );
            ByteArrayOutputStream container = new ByteArrayOutputStream();
            byte[] buf = new byte[16384];
            int len;
            while((len = stream.read(buf)) >= 0) {
                container.write(buf, 0, len);
            }
            return container.toByteArray();
        }
        catch (Exception ex) {
            Logger.getLogger(ObjectStorageService.class.getName()).log(Level.SEVERE, null, ex);
            throw new InvalidTokenException("Error getting file '" + dataName + "':" + ex.getMessage());
        }
    }
    public RemoteDocument getDocumentForToken(TokenParser tokenData, boolean wantXslt) throws InvalidTokenException {
            String dataName = wantXslt ? tokenData.getXslt() : tokenData.getIn();
            byte[] data = getFileForToken(dataName, tokenData.getCid());
            RemoteDocument ret = new RemoteDocument();
            ret.setBytes(data);
            return ret;
    }
    public void storeDocumentForToken(TokenParser tokenData, RemoteDocument document) throws InvalidTokenException {
        storeDocumentForToken(tokenData, document, "");
    }
    public void storeDocumentForToken(TokenParser tokenData, RemoteDocument document, String fileNameExtension) throws InvalidTokenException {
        try {
            try (ByteArrayInputStream bais = new ByteArrayInputStream(document.getBytes())) {
                getClient().putObject(PutObjectArgs.builder()
                        .bucket(tokenData.getCid())
                        .object(tokenData.getOut() + fileNameExtension)
                        .stream(bais, bais.available(), -1)
                        .build());
            }
        } catch (ErrorResponseException | InsufficientDataException
                | InternalException | InvalidKeyException
                | InvalidResponseException | IOException
                | NoSuchAlgorithmException | ServerException
                | XmlParserException  ex) {
            Logger.getLogger(ObjectStorageService.class.getName()).log(Level.SEVERE, null, ex);
            throw new InvalidTokenException();
        }
    }
    public DocumentMetadataDTO getTypeForToken(TokenParser token) {
        String filename = token.getIn();
        String xsltUrl = null;
        if(token.getXslt() != null) {
            xsltUrl = "${BEurl}/signing/getDocumentForToken?type=xslt&token=" + token.getRaw();
        }
        return new DocumentMetadataDTO(filename, mimeMap.getContentType(filename), xsltUrl, token.getPsfP(), token.getNoDownload(), token.getRequestDocumentReadConfirm());
    }
    public DocumentMetadataDTO getTypeForToken(String token) throws InvalidTokenException, InvalidKeyConfigException, TokenParser.TokenExpiredException {
        return getTypeForToken(parseToken(token, 5));
    }
    public RemoteDocument getDocumentForToken(String token, boolean wantXslt, int validMinutes) throws InvalidKeyConfigException, InvalidTokenException, TokenParser.TokenExpiredException {
        return getDocumentForToken(parseToken(token, validMinutes), wantXslt);
    }
    public RemoteDocument getDocumentForToken(String token) throws InvalidTokenException, InvalidKeyConfigException, TokenParser.TokenExpiredException {
        return getDocumentForToken(token, false, 5);
    }
    public RemoteDocument getDocumentForToken(String token, boolean wantXslt) throws InvalidTokenException, InvalidKeyConfigException, TokenParser.TokenExpiredException {
        return getDocumentForToken(token, wantXslt, 5);
    }
    public RemoteDocument getDocumentForToken(String token, int validMinutes) throws InvalidTokenException, InvalidKeyConfigException, TokenParser.TokenExpiredException {
        return getDocumentForToken(token, false, validMinutes);
    }
    public TokenParser parseToken(String token, int validMinutes) throws InvalidTokenException, InvalidKeyConfigException, TokenParser.TokenExpiredException {
        try {
            return new TokenParser(token, this, validMinutes);
        } catch (ParseException | JOSEException ex) {
            throw new InvalidTokenException(ex);
        }
    }

    public static class InvalidTokenException extends Exception {

        public InvalidTokenException() {
        }
        public InvalidTokenException(String mesg) {
            super(mesg);
        }
        public InvalidTokenException(Exception e) {
            super(e);
        }
    }

    public static class TokenCreationFailureException extends Exception {

        public TokenCreationFailureException() {
        }
    }

    public static class InvalidKeyConfigException extends Exception {

        public InvalidKeyConfigException() {
        }
    }
}
