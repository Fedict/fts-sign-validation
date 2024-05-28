package com.bosa.signandvalidation.job;

import com.bosa.signandvalidation.service.StorageService;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.Date;

@Service
public class MinioCleanupJob implements StorageService.BucketCleaner {

    private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(MinioCleanupJob.class);

    @Value("${delete.files.days:4,365}")
    private String deleteFilesDays;

    @Autowired
    private StorageService minio;

    private LocalDate startCleanup;
    private String secretBucket;
    private int daysToKeepFiles;
    private int daysToKeepTokens;

    @Scheduled(initialDelayString = "PT1S", fixedDelayString = "PT3H")

    public void refresh() {
        LOG.warn("Cleanup Starting (deleteFilesDays: " + deleteFilesDays + ")");
        startCleanup = LocalDate.now();
        secretBucket = minio.getSecretBucket();
        String[] bits = deleteFilesDays.split(",");
        daysToKeepFiles = Integer.parseInt(bits[0]);
        if (daysToKeepFiles < 2) daysToKeepFiles = 2;
        daysToKeepTokens = Integer.parseInt(bits[1]);
        if (daysToKeepTokens < 10) daysToKeepTokens = 10;

        LOG.warn("daysToKeepFiles:" + daysToKeepFiles + " - daysToKeepTokens:" + daysToKeepTokens);
        minio.cleanupBuckets(this);
        LOG.warn("Cleanup Done");
    }

    @Override
    public boolean shouldDelete(String bucketName, String path, boolean isDir, LocalDate lastModification) {
        return (!isDir && !path.startsWith("config/")) &&
                lastModification.plusDays(path.startsWith(secretBucket) ? daysToKeepTokens : daysToKeepFiles).isBefore(startCleanup);
    }
}
