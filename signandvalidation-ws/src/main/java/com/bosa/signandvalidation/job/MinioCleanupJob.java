package com.bosa.signandvalidation.job;

import com.bosa.signandvalidation.model.FileStoreInfo;
import com.bosa.signandvalidation.service.StorageService;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.time.LocalDateTime;

import static com.bosa.signandvalidation.controller.SigningController.KEYS_FOLDER;

@Service
public class MinioCleanupJob implements StorageService.BucketCleaner {

    private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(MinioCleanupJob.class);
    private static final byte[] EMPTY_FILE = new byte[0];

    @Value("${bucket.cleanup:}")
    private String config;

    @Autowired
    private StorageService minio;

    private LocalDateTime startCleanup;
    private String refreshFilename;
    private int daysToKeepFiles;
    private int daysToKeepTokens;
    private int hoursBetweenCleanups;

    @PostConstruct
    public void init() {
        if (config == null || !config.matches("\\d+,\\d+,\\d+")) {
            LOG.warn("No Cleanup. Config : " + config);
            config = null;
            return;
        }

        String[] bits = config.split(",");
        daysToKeepFiles = Integer.parseInt(bits[0]);
        daysToKeepTokens = Integer.parseInt(bits[1]);
        hoursBetweenCleanups = Integer.parseInt(bits[2]);

        // Safeguards
        if (daysToKeepFiles < 2) {
            LOG.warn("daysToKeepFiles too small :" + daysToKeepFiles);
            daysToKeepFiles = 2;
        }
        if (daysToKeepTokens < 10) {
            LOG.warn("daysToKeepTokens too small :" + daysToKeepTokens);
            daysToKeepTokens = 10;
        }
        if (hoursBetweenCleanups < 1) {
            LOG.warn("hoursBetweenCleanups too small :" + hoursBetweenCleanups);
            hoursBetweenCleanups = 1;
        }
        LOG.warn("Cleanup config : daysToKeepFiles:" + daysToKeepFiles + " - daysToKeepTokens:" + daysToKeepTokens + " - hoursBetweenCleanups:" + hoursBetweenCleanups);

        refreshFilename = KEYS_FOLDER + "bucket_cleanup";
    }

    @Scheduled(initialDelayString = "PT1M", fixedDelayString = "PT2H")
    public void refresh() {
        if (config == null) return;

        startCleanup = LocalDateTime.now();
        FileStoreInfo fi = null;
        fi = minio.getFileInfo(null, refreshFilename);
        if (fi.isFileExists() && fi.getLastModification().plusHours(hoursBetweenCleanups).isAfter(startCleanup)) return;

        minio.storeFile(null, refreshFilename, EMPTY_FILE);

        LOG.warn("Cleanup Starting");
        minio.cleanupBuckets(this);
        LOG.warn("Cleanup Done");
    }

    @Override
    public boolean shouldDelete(String bucketName, String path, boolean isDir, LocalDateTime lastModification) {
        return (!isDir && !path.startsWith("config/") && path.compareTo(refreshFilename) != 0) &&
                lastModification.plusDays(path.startsWith(KEYS_FOLDER) ? daysToKeepTokens : daysToKeepFiles).isBefore(startCleanup);
    }
}
