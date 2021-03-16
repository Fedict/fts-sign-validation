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
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
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
import java.util.Calendar;
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
    
    private Map<String, StoredKey> keys;

    private StoredKey defaultKey = null;
    private MimetypesFileTypeMap mimeMap;
    
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

    private static class TokenParser {
        private final String cid;
        private final String in;
        private final String out;
        private final String prof;
        private final Date iad;
        
        private static JWTClaimsSet ParseToken(String token, ObjectStorageService os) throws ParseException, JOSEException, InvalidKeyConfigException {
            JWEObject jweObject = JWEObject.parse(token);
            JWEHeader header = jweObject.getHeader();
            SecretKey key = os.getKeyForId(header.getKeyID());
            jweObject.decrypt(new DirectDecrypter(key));
            PlainJWT jwt = PlainJWT.parse(jweObject.getPayload().toString());
            return jwt.getJWTClaimsSet();
        }
        
        public TokenParser(String token, ObjectStorageService os) throws JOSEException, ParseException, InvalidKeyConfigException {
            JWTClaimsSet claims = ParseToken(token, os);
            cid = claims.getClaim("cid").toString();
            in = claims.getClaim("in").toString();
            out = claims.getClaim("out").toString();
            prof = claims.getClaim("prof").toString();
            iad = claims.getIssueTime();
        }
        public TokenParser(String token, ObjectStorageService os, int validMinutes) throws TokenExpiredException, ParseException, JOSEException, InvalidKeyConfigException {
            JWTClaimsSet claims = ParseToken(token, os);
            Date d = claims.getIssueTime();
            Calendar c = Calendar.getInstance();
            c.setTime(d);
            c.add(Calendar.MINUTE, validMinutes);
            Calendar now = Calendar.getInstance();
            if(c.compareTo(now) < 0) {
                throw new TokenExpiredException();
            }
            cid = claims.getClaim("cid").toString();
            in = claims.getClaim("in").toString();
            out = claims.getClaim("out").toString();
            prof = claims.getClaim("prof").toString();
            iad = d;
        }
        public String getCid() {
            return cid;
        }
        public String getIn() {
            return in;
        }
        public String getOut() {
            return out;
        }
        public String getProf() {
            return prof;
        }
        public Date getIad() {
            return iad;
        }
    }
    private SecretKey getKeyForId(String kid) throws InvalidKeyConfigException {
        try {
            if(defaultKey.getKid().equals(kid)) {
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
    public String getTokenForDocument(String bucket, String file, String outFile, String profile) throws TokenCreationFailureException, InvalidKeyConfigException {
        try {
            PlainJWT jwt = new PlainJWT(new JWTClaimsSet.Builder()
                    .claim("cid", bucket)
                    .claim("in", file)
                    .claim("out", outFile)
                    .claim("prof", profile)
                    .issueTime(new Date())
                    .build());
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
    public RemoteDocument getDocumentForToken(String token, int validMinutes) throws InvalidTokenException, InvalidKeyConfigException {
        RemoteDocument rv = new RemoteDocument();
        try {
            TokenParser tokenData = new TokenParser(token, this, validMinutes);
            InputStream stream = getClient().getObject(
                    GetObjectArgs.builder()
                            .bucket(tokenData.getCid())
                            .object(tokenData.getIn())
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
        } catch (TokenExpiredException ex) {
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
        } catch (JOSEException | ParseException | TokenExpiredException ex) {
            Logger.getLogger(ObjectStorageService.class.getName()).log(Level.SEVERE, null, ex);
            throw new InvalidTokenException();
        }
    }
    public RemoteDocument getDocumentForToken(String token) throws InvalidTokenException, InvalidKeyConfigException {
        return getDocumentForToken(token, 5);
    }

    public static class InvalidTokenException extends Exception {

        public InvalidTokenException() {
        }
    }

    public static class TokenCreationFailureException extends Exception {

        public TokenCreationFailureException() {
        }
    }

    private static class TokenExpiredException extends Exception {

        public TokenExpiredException() {
        }
    }

    public static class InvalidKeyConfigException extends Exception {

        public InvalidKeyConfigException() {
        }
    }
}
