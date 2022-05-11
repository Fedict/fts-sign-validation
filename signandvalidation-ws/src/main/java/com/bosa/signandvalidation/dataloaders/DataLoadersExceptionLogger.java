package com.bosa.signandvalidation.dataloaders;

import lombok.Getter;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.List;

import static com.bosa.signandvalidation.exceptions.Utils.logAndThrowEx;
import static org.springframework.http.HttpStatus.BAD_GATEWAY;

public class DataLoadersExceptionLogger {

    public enum Types {
        TimeStamp,
        OCSP,
        Policy,
        CRL,
        OnlineLoading,
        CertificateVerification
    };

    private static ThreadLocal exceptions = new ThreadLocal<>();

    public static void clearExceptions() {
        exceptions.remove();
    }

    public static void addException(Exception e, Types type) {
        Object o = exceptions.get();
        if (o == null) {
            o = new ArrayList<ExceptAndType>();
            exceptions.set(o);
        }
        ((List)o).add(new ExceptAndType(e, type));
    }

    public static void logAndThrow(Exception e) {
        if (e instanceof ResponseStatusException)
            throw (ResponseStatusException) e; // we already logged this exception

        List<ExceptAndType> threadExceptions = (List<ExceptAndType>)exceptions.get();
        if (threadExceptions != null) {
            Throwable t = e;
            while(t != null)  {
                for(ExceptAndType threadException : threadExceptions) {
                    if (threadException.getException() == t) logAndThrowEx(BAD_GATEWAY, threadException.getType().toString(), e);
                }
                t = t.getCause();
            }
        }
    }

    // log and throw any relevant exception that was throw during the last request
    public static void logAndThrow() {
        List<ExceptAndType> threadExceptions = (List<ExceptAndType>)exceptions.get();
        if (threadExceptions != null) {
            for (ExceptAndType threadException : threadExceptions) {
                logAndThrowEx(BAD_GATEWAY, threadException.getType().toString(), threadException.getException());
            }
        }
    }

    @Getter
    private static class ExceptAndType {
        private final Types type;
        private final Exception exception;

        public ExceptAndType(Exception exception, Types type) {
            this.exception = exception;
            this.type = type;
        }
    }
}
