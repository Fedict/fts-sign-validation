package com.bosa.signandvalidation.controller;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.logging.Logger;
import java.util.logging.Level;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/** Base class for the real Controller classes in this dir; provides logging and exception handling */
class ControllerBase {

    // TODO : check if SigningController.class is the right logger name to use for all controllers
    protected final Logger logger = Logger.getLogger(SigningController.class.getName());
}
