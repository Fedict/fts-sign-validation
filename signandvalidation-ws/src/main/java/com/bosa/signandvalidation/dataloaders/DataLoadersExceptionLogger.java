package com.bosa.signandvalidation.dataloaders;

import lombok.Getter;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static com.bosa.signandvalidation.config.ErrorStrings.ERROR_SUFFIX;
import static com.bosa.signandvalidation.exceptions.Utils.logAndThrowEx;
import static org.springframework.http.HttpStatus.BAD_GATEWAY;

public class DataLoadersExceptionLogger {

    public enum Types {
        TIMESTAMP,
        OCSP,
        POLICY,
        CRL,
        ONLINE_LOADING,
        CERT_VERIFICATION;

        public static String getMerged(Set<Types> types) {
            StringBuilder sb = new StringBuilder(60);
            for(Types type : types) sb.append(type.toString()).append("_");
            sb.setLength(sb.length() - 1);
            return sb.toString();
        }
    };

    private static ThreadLocal allThreadsExceptions = new ThreadLocal<>();

    public static void clearThreadExceptions() {
        allThreadsExceptions.remove();
    }

    // Add the exception to the list of exceptions that occurred for this thread run
    // At the end of the run the list must be cleared (see clearThreadExceptions) to start fresh for the next run
    public static void logExceptionForThread(Exception e, Types type) {
        Object threadExceptions = allThreadsExceptions.get();
        if (threadExceptions == null) {
            threadExceptions = new ArrayList<ExceptionAndType>();
            allThreadsExceptions.set(threadExceptions);
        }
        ((List<ExceptionAndType>)threadExceptions).add(new ExceptionAndType(e, type));
    }

    // Search for the exception or any of its causes was logged in the ThreadLocal list of exceptions that occurred during the run
    // If found, throw a "BAD GATEWAY" exception that reflects the actual cause more accurately.
    // Else return; the calling code is then responsible for throwing a generic exception
    public static void logAndThrow(Exception e) {
        if (e instanceof ResponseStatusException)
            throw (ResponseStatusException) e; // we already logged this exception

        List<ExceptionAndType> threadExceptions = (List<ExceptionAndType>) allThreadsExceptions.get();
        if (threadExceptions != null) {
            Set exceptionTypes = EnumSet.noneOf(Types.class);
            Throwable currentException = e;
            while(currentException != null)  {
                for(ExceptionAndType threadException : threadExceptions) {
                    if (threadException.getException() == currentException) exceptionTypes.add(threadException.getType());
                }
                currentException = currentException.getCause();
            }

            if (!exceptionTypes.isEmpty()) logAndThrowEx(BAD_GATEWAY, Types.getMerged(exceptionTypes) + ERROR_SUFFIX, e);
        }
    }

    // If any exception was logged during this thread run throw a "BAD GATEWAY" exception that reflects the actual cause more accurately.
    // Else return; the calling code is then responsible for throwing a generic exception
    public static void logAndThrow() {
        List<ExceptionAndType> threadExceptions = (List<ExceptionAndType>) allThreadsExceptions.get();
        if (threadExceptions != null) {
            Set exceptionTypes = EnumSet.noneOf(Types.class);
            for (ExceptionAndType threadException : threadExceptions) {
                exceptionTypes.add(threadException.getType());
            }
            if (!exceptionTypes.isEmpty()) logAndThrowEx(BAD_GATEWAY, Types.getMerged(exceptionTypes) + ERROR_SUFFIX, threadExceptions.get(0).getException());
        }
    }

    @Getter
    private static class ExceptionAndType {
        private final Types type;
        private final Exception exception;

        public ExceptionAndType(Exception exception, Types type) {
            this.exception = exception;
            this.type = type;
        }
    }
}
