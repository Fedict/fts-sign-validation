package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.TaskOutcomeDTO;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Logger;

public class TaskService {

    protected final Logger logger = Logger.getLogger(TaskService.class.getName());

    private final ConcurrentMap<UUID, CompletableFuture<Object>> runningTasks = new ConcurrentHashMap<>();

    //*****************************************************************************************

    public UUID addRunningTask(CompletableFuture<Object> future) {

        UUID taskId = UUID.randomUUID();
        runningTasks.put(taskId, future);
        manageTaskLifeCycle();
        return taskId;
    }

    //*****************************************************************************************

    public TaskOutcomeDTO getTaskOutcome(UUID uuid) {
        CompletableFuture<Object> task = runningTasks.get(uuid);
        if (task == null) return null;
        manageTaskLifeCycle();
        return new TaskOutcomeDTO(task);
    }

    //*****************************************************************************************

    private void manageTaskLifeCycle() {
        try {
            for(Map.Entry<UUID, CompletableFuture<Object>> task : runningTasks.entrySet()) {
                // Cancel running tasks over 5 minutes
                // Remove fully serviced tasks
                //if (task.getValue().)
            }
        } catch(Exception e) {
            logger.severe("Management : " + e.getMessage());
        }
    }

    //*****************************************************************************************

}
