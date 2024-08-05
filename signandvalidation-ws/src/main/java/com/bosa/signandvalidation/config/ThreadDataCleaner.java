package com.bosa.signandvalidation.config;

import com.bosa.signandvalidation.dataloaders.DataLoadersExceptionLogger;
import com.bosa.signandvalidation.exceptions.Utils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jetbrains.annotations.NotNull;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

@Component
public class ThreadDataCleaner implements HandlerInterceptor {

    @Override
    public void postHandle(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull Object handler, @Nullable ModelAndView modelAndView) throws Exception {
        DataLoadersExceptionLogger.clearThreadExceptions();
        Utils.clearMDCToken();
    }

}