package com.bosa.signandvalidation.job;

import com.bosa.signandvalidation.SignAndValidationApplication;
import com.bosa.signandvalidation.controller.SigningController;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.logging.Logger;

@Service
public class AbortJob {

    private static final Logger logger = Logger.getLogger(AbortJob.class.getName());

    @Scheduled(fixedDelay = 900000000, initialDelayString = "${shutdown.after.ms}")
    public void abort() {
        try {
            logger.info("SignAndValidationApplication.stop");
            SignAndValidationApplication.stop();
        } catch(Exception e) {
            logger.warning("SignAndValidationApplication.stop : Exception");
            logger.warning(e.toString());
            logger.warning(e.getMessage());
        }
        logger.info("System.exit");
        System.exit(0);
    }
}
