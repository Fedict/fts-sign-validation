package com.bosa.signandvalidation.job;

import com.bosa.signandvalidation.SignAndValidationApplication;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class AbortJob {

    @Scheduled(fixedDelay = 900000000, initialDelay = 30000)
    public void abort() {
        SignAndValidationApplication.stop();
        System.exit(0);
    }
}
