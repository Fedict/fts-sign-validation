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
import io.minio.messages.Bucket;
import io.minio.messages.DeleteError;
import io.minio.messages.DeleteObject;
import io.minio.messages.Item;
import lombok.Getter;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.bosa.signandvalidation.config.ErrorStrings.STORAGE_ERROR;
import static com.bosa.signandvalidation.exceptions.Utils.logAndThrowEx;
import static org.springframework.http.HttpStatus.*;

/**
 *
 * @author cmo
 */
@Service
public class StorageService {
    private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(StorageService.class);

    @Value("${objectstorage.endpoint}")
    private String S3Endpoint;

    @Value("${objectstorage.accesskey}")
    private String accessKey;

    @Value("${objectstorage.secretkey}")
    private String secretKey;

    @Getter
    @Value("${objectstorage.secretbucket}")
    private String secretBucket;

    private MinioClient client;

    private MinioClient getClient() {
        if (client == null) {
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
            Logger.getLogger(StorageService.class.getName()).log(Level.SEVERE, "Exception :" + ex.toString() + " - Cause:" + ex.getCause() + " - Message :" + ex.getMessage(), ex);
            return false;
        }
    }

    public InputStream getFileAsStream(String bucket, String name) {
        try {
            if (bucket == null) bucket = secretBucket;
            return getClient().getObject(GetObjectArgs.builder().bucket(bucket).object(name).build());

        } catch (Exception e) {
            logAndThrow("getting", name, e);
        }
        return null;
    }

    public String getFileAsB64String(String bucket, String name) {
        return Base64.getEncoder().encodeToString(getFileAsBytes(bucket, name, true));
    }

    public byte[] getFileAsBytes(String bucket, String path, boolean getFileSize) {
        byte[] outBytes = null;
        InputStream inStream = null;
        try {
            if (bucket == null) bucket = secretBucket;
            int size = 8192;
            if (getFileSize) {
                StatObjectResponse so = getClient().statObject(StatObjectArgs.builder().bucket(bucket).object(path).build());
                size = (int) so.size();
            }

            inStream = getClient().getObject(GetObjectArgs.builder().bucket(bucket).object(path).build());
            ByteArrayOutputStream out = new ByteArrayOutputStream(size);
            byte[] buffer = new byte[8192];
            int read;
            while ((read = inStream.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            inStream.close();
            outBytes = out.toByteArray();
        } catch (Exception e) {
            logAndThrow("getting", path, e);
        } finally {
            if (inStream != null) {
                try {
                    inStream.close();
                } catch (IOException ignored) {
                }
            }
        }
        return outBytes;
    }

    public String getFileAsString(String bucket, String name) {
        InputStream stream = null;
        try {
            if (bucket == null) bucket = secretBucket;
            stream = getClient().getObject(GetObjectArgs.builder().bucket(bucket).object(name).build());
            StringBuilder sb = new StringBuilder(32768);
            byte[] buffer = new byte[2048];
            while (true) {
                int read = stream.read(buffer);
                if (read < 0) break;
                sb.append(new String(buffer));
            }
            stream.close();
            return sb.toString();
        } catch (Exception e) {
            logAndThrow("getting", name, e);
        } finally {
            if (stream != null) {
                try {
                    stream.close();
                } catch (IOException ignored) {
                }
            }
        }
        return null;
    }

    public FileStoreInfo getFileInfo(String bucket, String name) {
        try {
            if (bucket == null) bucket = secretBucket;
            StatObjectResponse so = getClient().statObject(StatObjectArgs.builder().bucket(bucket).object(name).build());
            return new FileStoreInfo(MediaTypeUtil.getMediaTypeFromFilename(name), so.etag(), so.size(), LocalDateTime.from(so.lastModified()));
        } catch(ErrorResponseException e) {
            return new FileStoreInfo(); // File not found
        } catch (Exception e) {
            logAndThrow("getting info for", name, e);
        }
        return null;
    }

    public void storeFile(String bucket, String name, byte[] content) {
        try {
            if (bucket == null) bucket = secretBucket;
            getClient().putObject(PutObjectArgs.builder()
                    .bucket(bucket)
                    .object(name)
                    .stream(new ByteArrayInputStream(content), content.length, -1)
                    .build()
            );
        } catch (Exception e) {
            logAndThrow("saving", name, e);
        }
    }

    private void logAndThrow(String oper, String fileName, Exception e) {
        String msg = "Error while " + oper + " file '" + fileName;

        HttpStatus s = INTERNAL_SERVER_ERROR;
        if (e instanceof SocketTimeoutException) s = GATEWAY_TIMEOUT;
        else if (e instanceof IOException) s = BAD_GATEWAY;
        logAndThrowEx(s, STORAGE_ERROR, msg, e);
    }

    public void cleanupBuckets(BucketCleaner cleaner) {
        String bucketName = "none";
        String fileName = bucketName;
        try {
            MinioClient minioClient = getClient();
            StringBuilder sb = new StringBuilder();
            List<DeleteObject> toDelete = new ArrayList<DeleteObject>();
            for (Bucket bucket : minioClient.listBuckets()) {
                sb.setLength(0);
                toDelete.clear();
                bucketName = bucket.name();
                try {
                    Iterable<Result<Item>> results = minioClient.listObjects(ListObjectsArgs.builder().bucket(bucketName).recursive(true).build());
                    for (Result<Item> r : results) {
                        Item i = r.get();
                        fileName = i.objectName();
                        if (cleaner.shouldDelete(bucketName, fileName, i.isDir(), i.isDir() ? null : LocalDateTime.from(i.lastModified()))) {
                            toDelete.add(new DeleteObject(fileName));
                            sb.append(fileName);
                            sb.append(", ");
                        }
                    }
                } catch (Exception e) {
                    LOG.error("Cleanup skipping bucket : " + bucketName + " because of exception :" + e.getMessage());
                }
                if (!toDelete.isEmpty()) {
                    sb.setLength(sb.length() - 2);
                    LOG.info("Deleting bucket '" + bucketName + "' (" + sb + "')");
                    try {
                        Iterable<Result<DeleteError>> deleteErrors = minioClient.removeObjects(RemoveObjectsArgs.builder().bucket(bucketName).objects(toDelete).build());
                        for (Result<DeleteError> deleteError : deleteErrors) {
                            DeleteError error = deleteError.get();
                            LOG.warn("Delete error : " + error.objectName() + " - " + error.code());
                        }
                    } catch (Exception e) {
                        LOG.error("Cleanup deletion exception :" + e.getMessage());
                    }
                }
            }

        } catch (Exception e) {
            logAndThrow("Cleaning", bucketName + "-" + fileName, e);
        }
    }

    public interface BucketCleaner {
        boolean shouldDelete(String bucketName, String path, boolean isDir, LocalDateTime lastModification);
    }
}