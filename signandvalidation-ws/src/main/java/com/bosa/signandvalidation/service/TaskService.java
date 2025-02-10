package com.bosa.signandvalidation.service;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.logging.Logger;

@Service
public class TaskService {

    private final Logger logger = Logger.getLogger(TaskService.class.getName());

    private final Map<UUID, TaskInfo> runningTasks = new ConcurrentHashMap<>();

    private Date now;

    //*****************************************************************************************

    public UUID addRunningTask(Future<Object> future) {

        now = new Date();
        UUID taskId = UUID.randomUUID();
        runningTasks.put(taskId, new TaskInfo(future, now));
        manageTaskLifeCycle();
        return taskId;
    }

    //*****************************************************************************************

    public Object getTaskResult(UUID uuid) throws ExecutionException, InterruptedException {
        now = new Date();
        TaskInfo ti = runningTasks.get(uuid);
        if (ti == null) return null;
        Future<Object> future = ti.getFuture();
        if (!future.isDone()) {
            manageTaskLifeCycle();
            return Boolean.FALSE;
        }
        runningTasks.remove(uuid);
        Object o = future.get();
        if (o == null) o = Boolean.TRUE;
        return o;
    }

    //*****************************************************************************************

    private void manageTaskLifeCycle() {
        try {
            for(Map.Entry<UUID, TaskInfo> entry : runningTasks.entrySet()) {
                TaskInfo ti = entry.getValue();
                // Cancel tasks over 5 minutes
                if (ti.getDeathDate().before(now)) {
                    ti.getFuture().cancel(true) ;
                    runningTasks.remove(entry.getKey());
                }
            }
        } catch(Exception e) {
            logger.severe("Management : " + e.getMessage());
        }
    }

    //*****************************************************************************************

    @Data
    @NoArgsConstructor
    private static class TaskInfo {
        private Future<Object> future;
        private Date deathDate;

        public TaskInfo(Future<Object> future, Date now) {
            this.future = future;
            this.deathDate = DateUtils.addMinutes(now, 5);
        }
    }

    //*****************************************************************************************
}
