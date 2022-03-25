/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.FileStoreInfo;
import com.bosa.signandvalidation.utils.MediaTypeUtil;
import io.minio.*;
import io.minio.errors.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author cmo
 */
@Service
public class StorageService {
    @Value("${objectstorage.endpoint}")
    private String S3Endpoint;

    @Value("${objectstorage.accesskey}")
    private String accessKey;

    @Value("${objectstorage.secretkey}")
    private String secretKey;

    @Value("${objectstorage.secretbucket}")
    private String secretBucket;

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
            Logger.getLogger(StorageService.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }
    }

    public InputStream getFileAsStream(String bucket, String name) throws InvalidKeyConfigException {
        try {
            if (bucket == null) bucket = secretBucket;
            return getClient().getObject(GetObjectArgs.builder().bucket(bucket).object(name).build());

        } catch (MinioException | IOException | InvalidKeyException | NoSuchAlgorithmException e) {
            logAndThrow("getting", name, e);
        }
        return null;
    }

    public String getFileAsB64String(String bucket, String name) throws InvalidKeyConfigException {
        return Base64.getEncoder().encodeToString(getFileAsBytes(bucket, name, true));
    }

    public byte[] getFileAsBytes(String bucket, String name, boolean getSize) throws InvalidKeyConfigException {
        int read;
        byte[] outBytes = null;
        InputStream inStream = null;
        try {
            if (bucket == null) bucket = secretBucket;
            int size = 8192;
            if (getSize) {
                StatObjectResponse so = getClient().statObject(StatObjectArgs.builder().bucket(bucket).object(name).build());
                size = (int) so.size();
            }

            inStream = getClient().getObject(GetObjectArgs.builder().bucket(bucket).object(name).build());
            ByteArrayOutputStream out = new ByteArrayOutputStream(size);
            byte[] buffer = new byte[8192];
            while ((read = inStream.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            inStream.close();
            outBytes = out.toByteArray();
        } catch (ErrorResponseException | InsufficientDataException
                | InternalException | InvalidKeyException
                | InvalidResponseException | IOException
                | NoSuchAlgorithmException | ServerException
                | XmlParserException e) {
            logAndThrow("getting", name, e);
        } finally {
            if (inStream != null) {
                try {
                    inStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return outBytes;
    }

    public String getFileAsString(String bucket, String name) throws InvalidKeyConfigException {
        InputStream stream = null;
        try {
            if (bucket == null) bucket = secretBucket;
            stream = getClient().getObject(GetObjectArgs.builder().bucket(bucket).object(name).build());
            StringBuilder sb = new StringBuilder(32768);
            byte[] buffer = new byte[2048];
            while(true) {
                int read = stream.read(buffer);
                if (read < 0) break;
                sb.append(new String(buffer));
            }
            stream.close();
            return sb.toString();
        } catch (MinioException | IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            logAndThrow("getting", name, e);
        } finally {
            if (stream != null) {
                try {
                    stream.close();
                } catch (IOException ignored) { }
            }
        }
        return null;
    }

    public FileStoreInfo getFileInfo(String bucket, String name) throws InvalidKeyConfigException {
        try {
            if (bucket == null) bucket = secretBucket;
            StatObjectResponse so = getClient().statObject(StatObjectArgs.builder().bucket(bucket).object(name).build());
            return new FileStoreInfo(MediaTypeUtil.getMediaTypeFromFilename(name), so.etag(), so.size());

        } catch (MinioException | IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            logAndThrow("getting info for", name, e);
        }
        return null;
    }

    public void storeFile(String bucket, String name, byte[] content) throws InvalidKeyConfigException {
        try {
            if (bucket == null) bucket = secretBucket;
            getClient().putObject(PutObjectArgs.builder()
                    .bucket(bucket)
                    .object(name)
                    .stream(new ByteArrayInputStream(content), content.length, -1)
                    .build()
            );
        } catch (MinioException | IOException | NoSuchAlgorithmException |  InvalidKeyException e) {
            logAndThrow("saving", name, e);
        }
    }

    private void logAndThrow(String oper, String fileName, Exception e) throws InvalidKeyConfigException {
        Logger.getLogger(StorageService.class.getName()).log(Level.SEVERE, null, e);

        throw new InvalidKeyConfigException("Error while " + oper + " file '" + fileName + "' : '" + e.getMessage() + "'", e);
    }

    public static class InvalidKeyConfigException extends Exception {
        public InvalidKeyConfigException(String message, Throwable e) {
            super(message, e);
        }
    }

}
