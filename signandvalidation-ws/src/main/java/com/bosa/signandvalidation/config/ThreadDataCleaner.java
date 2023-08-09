package com.bosa.signandvalidation.config;

import com.bosa.signandvalidation.dataloaders.DataLoadersExceptionLogger;
import com.bosa.signandvalidation.exceptions.Utils;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class ThreadDataCleaner extends HandlerInterceptorAdapter {

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, @Nullable ModelAndView modelAndView) throws Exception {
        DataLoadersExceptionLogger.clearThreadExceptions();
        Utils.clearMDCToken();
    }

}