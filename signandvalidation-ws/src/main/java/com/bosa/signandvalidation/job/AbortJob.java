package com.bosa.signandvalidation.job;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.logging.Logger;

@Service
public class AbortJob {

    @Scheduled(cron = "${shutdown.cron}")
    public void abort() {
        Logger.getLogger(AbortJob.class.getName()).info("System.exit");
        System.exit(0);
    }
}
