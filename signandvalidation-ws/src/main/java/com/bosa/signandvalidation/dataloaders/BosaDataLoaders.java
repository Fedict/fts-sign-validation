package com.bosa.signandvalidation.dataloaders;

import lombok.Getter;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.List;

import static com.bosa.signandvalidation.config.ErrorStrings.TIMESTAMP_ERROR;
import static com.bosa.signandvalidation.exceptions.Utils.logAndThrowEx;
import static org.springframework.http.HttpStatus.BAD_GATEWAY;

public class BosaDataLoaders {

    public enum Types {
        TimeStamp,
        OCSP,
        Policy,
        CRL,
        OnlineLoading, CertificateVerification
    };

    private static ThreadLocal exceptions = new ThreadLocal<>();

    public static void setException(Exception e, Types type) {
        Object o = exceptions.get();
        if (o == null) {
            o = new ArrayList<EaT>();
            exceptions.set(o);
        }
        ((List)o).add(new EaT(e, type));
    }

    public static void logAndThrow(Exception e) {
        if (e instanceof ResponseStatusException)
            throw (ResponseStatusException) e; // we already logged this exception

        List<EaT> originalExceptions = (List<EaT>)exceptions.get();
        Throwable t = e;
        while(t != null)  {
            for(EaT originalException : originalExceptions) {
                if (originalException.getException() == t) logAndThrowEx(BAD_GATEWAY, TIMESTAMP_ERROR, e);
            }
            t = t.getCause();
        }
    }

    @Getter
    private static class EaT {
        private final Types type;
        private final Exception exception;

        public EaT(Exception exception, Types type) {
            this.exception = exception;
            this.type = type;
        }
    }
}
