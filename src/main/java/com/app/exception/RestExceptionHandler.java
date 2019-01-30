package com.app.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.BindException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestControllerAdvice
public class RestExceptionHandler {
    
	@ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<?> handleUsernameNotFoundException(UsernameNotFoundException e) {
    	ExceptionResponse param = ExceptionResponse.builder().message("No user found with email").build();
        return ResponseEntity.status(HttpStatus.CONFLICT).body(param);
    }
	
	@ExceptionHandler(DisabledException.class)
    public ResponseEntity<?> handleDisabledException(DisabledException e) {
    	ExceptionResponse param = ExceptionResponse.builder().message("User is disabled").build();
        return ResponseEntity.status(HttpStatus.CONFLICT).body(param);
    }
    
	@ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<?> handleBadCredentialsException(BadCredentialsException e) {
    	ExceptionResponse param = ExceptionResponse.builder().message("Bad credentials").build();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(param);
    }
	
	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<?> handleAccessDeniedException(AccessDeniedException e){
		ExceptionResponse param = ExceptionResponse.builder().message("Unauthorized").build();
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(param);
	}
	
	@ExceptionHandler(NoHandlerFoundException.class)
	@ResponseStatus(HttpStatus.NOT_FOUND)
	public ResponseEntity<?> handleNoHandlerFoundException(NoHandlerFoundException e) {
		ExceptionResponse param = ExceptionResponse.builder().message("Not Found").build();
		return ResponseEntity.status(HttpStatus.NOT_FOUND).body(param);
	}
	
	@ExceptionHandler(value = HttpRequestMethodNotSupportedException.class)
	@ResponseStatus(HttpStatus.METHOD_NOT_ALLOWED)
	protected Object handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException e) throws Exception {
		ExceptionResponse param = ExceptionResponse.builder().message("Not Allowed Method").build();
		return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(param);
	}
	
	@ExceptionHandler(AlgorithmException.class)
	public ResponseEntity<?> handleAlgorithmException(AlgorithmException e) {
		ExceptionResponse param = ExceptionResponse.builder().message("AES Algorithm Error").build();
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(param);
	}
	
	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<?> handleMethodArgumentNotValidException(MethodArgumentNotValidException e) {
		ExceptionResponse param = ExceptionResponse.builder().message("Validation Error").build();
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(param);
	}
	
	@ExceptionHandler(BindException.class)
	public ResponseEntity<?> handleMethodArgumentNotValidException(BindException e) {
		ExceptionResponse param = ExceptionResponse.builder().message("Validation Error").build();
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(param);
	}
	
	@ExceptionHandler(Exception.class)
	public ResponseEntity<?> handleMethodException(Exception e) {
		log.error("System Error", e);
		ExceptionResponse param = ExceptionResponse.builder().message("System Error").build();
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(param);
	}
}
