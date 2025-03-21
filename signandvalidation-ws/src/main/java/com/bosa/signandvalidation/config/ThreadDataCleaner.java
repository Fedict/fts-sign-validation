package com.bosa.signandvalidation.config;

import com.bosa.signandvalidation.dataloaders.DataLoadersExceptionLogger;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jetbrains.annotations.NotNull;
import org.slf4j.MDC;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

@Component
public class ThreadDataCleaner implements HandlerInterceptor {

    @Override
    public void postHandle(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull Object handler, @Nullable ModelAndView modelAndView) {
        clearAll();
    }

    public static void clearAll() {
        DataLoadersExceptionLogger.clearThreadExceptions();
        // Clear Token and all other MDC data for this thread
        MDC.clear();
        ThreadedCertificateVerifier.clearInteceptions();
    }
}