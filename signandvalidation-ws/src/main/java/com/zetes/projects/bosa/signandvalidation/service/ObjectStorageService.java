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
import com.zetes.projects.bosa.signandvalidation.model.DocumentMetadataDTO;
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
    public String getTokenForDocument(String bucket, String file, String outFile, String profile, String xslt) throws TokenCreationFailureException, InvalidKeyConfigException {
        try {
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                    .claim("cid", bucket)
                    .claim("in", file)
                    .claim("out", outFile)
                    .claim("prof", profile)
                    .issueTime(new Date());
            if(xslt != null) {
                builder.claim("xslt", xslt);
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
        }
    }
    public RemoteDocument getDocumentForToken(String token, boolean wantXslt, int validMinutes) throws InvalidTokenException, InvalidKeyConfigException {
        RemoteDocument rv = new RemoteDocument();
        try {
            TokenParser tokenData = new TokenParser(token, this, validMinutes);
            String dataName = wantXslt ? tokenData.getXslt() : tokenData.getIn();
            InputStream stream = getClient().getObject(
                    GetObjectArgs.builder()
                            .bucket(tokenData.getCid())
                            .object(dataName)
                            .build()
            );
            ByteArrayOutputStream container = new ByteArrayOutputStream();
            byte[] buf = new byte[16384];
            int len;
            while((len = stream.read(buf)) >= 0) {
                container.write(buf, 0, len);
            }
            rv.setBytes(container.toByteArray());
            return rv;
        } catch (ParseException | JOSEException | ErrorResponseException
                | InsufficientDataException | InternalException
                | InvalidKeyException | InvalidResponseException
                | IOException | NoSuchAlgorithmException | ServerException
                | XmlParserException ex) {
            Logger.getLogger(ObjectStorageService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (TokenParser.TokenExpiredException ex) {
            throw new InvalidTokenException();
        }
        throw new InvalidTokenException();
    }
    public void storeDocumentForToken(String token, RemoteDocument document) throws InvalidTokenException, InvalidKeyConfigException {
        try {
            TokenParser tokenData = new TokenParser(token, this);
            try (ByteArrayInputStream bais = new ByteArrayInputStream(document.getBytes())) {
                getClient().putObject(PutObjectArgs.builder()
                        .bucket(tokenData.getCid())
                        .object(tokenData.getOut())
                        .stream(bais, bais.available(), -1)
                        .build());
            }
        } catch (ErrorResponseException | InsufficientDataException
                | InternalException | InvalidKeyException
                | InvalidResponseException | IOException
                | NoSuchAlgorithmException | ServerException
                | XmlParserException | JOSEException | ParseException ex) {
            Logger.getLogger(ObjectStorageService.class.getName()).log(Level.SEVERE, null, ex);
            throw new InvalidTokenException();
        }
    }
    public DocumentMetadataDTO getTypeForToken(String token) throws InvalidTokenException, InvalidKeyConfigException {
        try {
            String filename = new TokenParser(token, this, 5).getIn();
            return new DocumentMetadataDTO(filename, mimeMap.getContentType(filename));
        } catch (JOSEException | ParseException
                | TokenParser.TokenExpiredException ex) {
            Logger.getLogger(ObjectStorageService.class.getName()).log(Level.SEVERE, null, ex);
            throw new InvalidTokenException();
        }
    }
    public RemoteDocument getDocumentForToken(String token) throws InvalidTokenException, InvalidKeyConfigException {
        return getDocumentForToken(token, false, 5);
    }
    public RemoteDocument getDocumentForToken(String token, boolean wantXslt) throws InvalidTokenException, InvalidKeyConfigException {
        return getDocumentForToken(token, wantXslt, 5);
    }
    public RemoteDocument getDocumentForToken(String token, int validMinutes) throws InvalidTokenException, InvalidKeyConfigException {
        return getDocumentForToken(token, false, validMinutes);
    }

    public static class InvalidTokenException extends Exception {

        public InvalidTokenException() {
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
