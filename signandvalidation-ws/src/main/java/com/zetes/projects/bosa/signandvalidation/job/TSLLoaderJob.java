package com.zetes.projects.bosa.signandvalidation.job;

import eu.europa.esig.dss.tsl.job.TLValidationJob;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;

@Service
public class TSLLoaderJob {

    @Value("${cron.tl.loader.enable}")
    private boolean enable;

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
        }
    }

}
