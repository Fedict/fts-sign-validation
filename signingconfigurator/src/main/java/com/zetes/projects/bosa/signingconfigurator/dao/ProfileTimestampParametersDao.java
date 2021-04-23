package com.zetes.projects.bosa.signingconfigurator.dao;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zetes.projects.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.zetes.projects.bosa.signingconfigurator.model.ProfileTimestampParameters;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ProfileTimestampParametersDao {
    @Value("${profileconfig.jsonpath}")
    private String JSON_PATH;
    
    private final Map<String, ProfileTimestampParameters> parameters;
    private ProfileTimestampParameters defParam;
    private boolean isInited = false;
    private static final Logger logger = Logger.getLogger(ProfileTimestampParametersDao.class.getName());
    
    private class JsonFileFilter implements FilenameFilter {
        @Override
        public boolean accept (File dir, String name) {
            return name.toLowerCase().endsWith(".json");
        }
    }
    
    ProfileTimestampParametersDao() {
        parameters = new LinkedHashMap();
    }
    void readProfiles() throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        File folder;
        if(JSON_PATH == null) {
            folder = new File(".");
        } else {
            folder = new File(JSON_PATH + "/timestamp");
        }
        
        for (final File jsonFile : folder.listFiles(new JsonFileFilter())) {
            ProfileTimestampParameters p = mapper.readValue(jsonFile, ProfileTimestampParameters.class);
            if(p.getIsDefault()) {
                defParam = p;
            }
            parameters.put(p.getProfileId(), p);
        }
    }
    public ProfileTimestampParameters findDefault() throws ProfileNotFoundException {
        if(!isInited) {
            try {
                readProfiles();
            } catch (IOException ex) {
                logger.log(Level.SEVERE, null, ex);
                throw new ProfileNotFoundException("Profiles could not be loaded");
            }
        }
        if(defParam != null) {
            return defParam;
        }
        throw new ProfileNotFoundException("Default profile not found");
    }
    
    public ProfileTimestampParameters findById(String id) throws ProfileNotFoundException {
        if(!isInited) {
            try {
                readProfiles();
            } catch (IOException ex) {
                logger.log(Level.SEVERE, null, ex);
                throw new ProfileNotFoundException("Profiles could not be loaded");
            }
        }
        if(parameters.containsKey(id)) {
            return parameters.get(id);
        }
        throw new ProfileNotFoundException(String.format("%s not found",id));
    }
    public void deleteAll() {
        defParam = null;
        parameters.clear();
    }
    public void save(ProfileTimestampParameters p) {
        if(!isInited) {
            try {
                readProfiles();
            } catch (IOException ex) {
                logger.log(Level.SEVERE, null, ex);
            }
        }
        if(p.getIsDefault()) {
            defParam = p;
        }
        parameters.put(p.getProfileId(), p);
    }
}
