package com.bosa.signandvalidation.job;

import eu.europa.esig.dss.tsl.job.TLValidationJob;
import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class TSLLoaderJob {

    @Value("${cron.tl.loader.enable}")
    private boolean enable;

    @Value("${lotl.completed.markfile}")
    private String MARKFILE;

    @Autowired
    private TLValidationJob job;

    @PostConstruct
    public void init() {
        job.offlineRefresh();
    }

    @Scheduled(initialDelayString = "${cron.initial.delay.tl.loader}", fixedDelayString = "${cron.delay.tl.loader}")
    public void refresh() {
        if (enable) {
            job.onlineRefresh();
            try {
                if(MARKFILE != null && MARKFILE.length() > 0) {
                    File file = new File(MARKFILE);
                    file.createNewFile();
                }
            } catch (IOException ex) {
                    Logger.getLogger(TSLLoaderJob.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

}
