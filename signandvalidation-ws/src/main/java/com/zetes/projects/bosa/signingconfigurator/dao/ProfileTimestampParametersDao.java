package com.zetes.projects.bosa.signingconfigurator.dao;

import com.zetes.projects.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.zetes.projects.bosa.signingconfigurator.model.ProfileTimestampParameters;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.springframework.stereotype.Component;

@Component
public class ProfileTimestampParametersDao extends JsonDao {
    private final Map<String, ProfileTimestampParameters> parameters;
    private static final Logger logger = Logger.getLogger(ProfileTimestampParametersDao.class.getName());
    
    ProfileTimestampParametersDao() {
        parameters = new LinkedHashMap();
        profileName = "timestamp";
    }
    public ProfileTimestampParameters findDefault() throws ProfileNotFoundException {
        if(!isInited) {
            try {
                readProfiles(parameters, ProfileTimestampParameters.class);
            } catch (IOException ex) {
                logger.log(Level.SEVERE, null, ex);
                throw new ProfileNotFoundException("Profiles could not be loaded");
            }
        }
        if(defParam != null) {
            return (ProfileTimestampParameters)defParam;
        }
        throw new ProfileNotFoundException("Default profile not found");
    }
    
    public ProfileTimestampParameters findById(String id) throws ProfileNotFoundException {
        if(!isInited) {
            try {
                readProfiles(parameters, ProfileTimestampParameters.class);
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
        isInited = true;
    }
    public void save(ProfileTimestampParameters p) {
        if(!isInited) {
            try {
                readProfiles(parameters, ProfileTimestampParameters.class);
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
