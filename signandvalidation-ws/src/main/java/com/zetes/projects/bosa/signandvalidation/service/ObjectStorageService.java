/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zetes.projects.bosa.signandvalidation.service;

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
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyGenerator;
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

    private SecretKey _key;
    
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
    
    private String getKid() {
        return "aaa";
    }
    
    public ObjectStorageService() {
    }
    private static class TokenParser {
        private final String cid;
        private final String in;
        private final String out;
        private final String prof;
        private final Date iad;
        
        public TokenParser(String token, ObjectStorageService os) throws JOSEException, ParseException {
            JWEObject jweObject = JWEObject.parse(token);
            JWEHeader header = jweObject.getHeader();
            SecretKey key = os.getKeyForId(header.getKeyID());
            jweObject.decrypt(new DirectDecrypter(key));
            PlainJWT jwt = PlainJWT.parse(jweObject.getPayload().toString());
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            cid = claims.getClaim("cid").toString();
            in = claims.getClaim("in").toString();
            out = claims.getClaim("out").toString();
            prof = claims.getClaim("prof").toString();
            iad = claims.getIssueTime();
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
    // TODO: implement properly so the key is generated externally
    private SecretKey getKeyForId(String kid) {
        if(_key != null) {
            return _key;
        }
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            _key = keyGen.generateKey();
            return _key;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ObjectStorageService.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    public String getProfileForToken(String token) throws JOSEException, ParseException {
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
    public String getTokenForDocument(String bucket, String file, String outFile, String profile) throws TokenCreationFailureException {
        try {
            PlainJWT jwt = new PlainJWT(new JWTClaimsSet.Builder()
                    .claim("cid", bucket)
                    .claim("in", file)
                    .claim("out", outFile)
                    .claim("prof", profile)
                    .issueTime(new Date())
                    .build());
            JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128GCM)
                    .keyID(getKid())
                    .build(), new Payload(jwt.serialize()));
            jweObject.encrypt(new DirectEncrypter(getKeyForId(getKid())));
            return jweObject.serialize();
        } catch (JOSEException ex) {
            Logger.getLogger(ObjectStorageService.class.getName()).log(Level.SEVERE, null, ex);
            throw new TokenCreationFailureException();
        }
    }
    public RemoteDocument getDocumentForToken(String token, int validMinutes) throws InvalidTokenException {
        RemoteDocument rv = new RemoteDocument();
        try {
            TokenParser tokenData = new TokenParser(token, this);
            Date iad = tokenData.getIad();
            Calendar c = Calendar.getInstance();
            c.setTime(iad);
            c.add(Calendar.MINUTE, validMinutes);
            Calendar now = Calendar.getInstance();
            if(c.compareTo(now) < 0) {
                throw new InvalidTokenException();
            }
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
        }
        throw new InvalidTokenException();
    }
    public void storeDocumentForToken(String token, RemoteDocument document) throws InvalidTokenException {
        try {
            TokenParser tokenData = new TokenParser(token, this);
            ByteArrayInputStream bais = new ByteArrayInputStream(document.getBytes());
            getClient().putObject(PutObjectArgs.builder()
                    .bucket(tokenData.getCid())
                    .object(tokenData.getOut())
                    .stream(bais, bais.available(), -1)
                    .build());
            bais.close();
        } catch (ErrorResponseException | InsufficientDataException
                | InternalException | InvalidKeyException
                | InvalidResponseException | IOException
                | NoSuchAlgorithmException | ServerException
                | XmlParserException | JOSEException | ParseException ex) {
            Logger.getLogger(ObjectStorageService.class.getName()).log(Level.SEVERE, null, ex);
            throw new InvalidTokenException();
        }
    }
    public RemoteDocument getDocumentForToken(String token) throws InvalidTokenException {
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
}
