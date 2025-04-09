package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.ASyncTaskDTO;
import com.bosa.signandvalidation.model.ASyncTaskStatusDTO;
import jakarta.servlet.http.HttpSession;
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

import static com.bosa.signandvalidation.exceptions.Utils.logger;

@Service
public class TaskService {

    private final Logger logger = Logger.getLogger(TaskService.class.getName());

    private final Map<UUID, TaskInfo> runningTasks = new ConcurrentHashMap<>();

    private Date now;

    //*****************************************************************************************

    public ASyncTaskDTO addRunningTask(Future<Object> future, String token) {
        now = new Date();
        UUID taskId = UUID.randomUUID();
        logger.info("TASK status : " + taskId);
        runningTasks.put(taskId, new TaskInfo(future, now, token));
        manageTaskLifeCycle();
        return new ASyncTaskDTO(taskId);
    }

    //*****************************************************************************************

    public Object getTaskResult(UUID uuid) throws ExecutionException, InterruptedException {
        now = new Date();
        TaskInfo ti = runningTasks.get(uuid);
        if (ti == null) return null;
        Future<Object> future = ti.getFuture();
        Object o = ASyncTaskStatusDTO.RUNNING;
        if (future.isDone()) {
            logger.info("TASK Done : " + uuid);
            runningTasks.remove(uuid);
            o = future.get();
            if (o == null) o = ASyncTaskStatusDTO.DONE;
        } else manageTaskLifeCycle();
        return o;
    }

    //*****************************************************************************************

    private void manageTaskLifeCycle() {
        try {
            for(Map.Entry<UUID, TaskInfo> entry : runningTasks.entrySet()) {
                TaskInfo ti = entry.getValue();
                // Cancel expired tasks
                if (ti.getDeathDate().before(now)) {
                    logger.warning("TASK Canceling : " + entry.getKey() + " - " + ti.getToken());
                    ti.getFuture().cancel(true) ;
                    runningTasks.remove(entry.getKey());
                }
            }
        } catch(Exception e) {
            logger.severe("TASK Management : " + e.getMessage());
        }
    }

    //*****************************************************************************************

    @Data
    @NoArgsConstructor
    private static class TaskInfo {
        private Future<Object> future;
        private Date deathDate;
        private String token;

        public TaskInfo(Future<Object> future, Date now, String token) {
            this.future = future;
            this.deathDate = DateUtils.addMinutes(now, 5);
            this.token = token;
        }
    }

    //*****************************************************************************************
}
