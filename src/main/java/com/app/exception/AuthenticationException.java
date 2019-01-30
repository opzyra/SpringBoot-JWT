package com.app.exception;

public class AuthenticationException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public AuthenticationException(Throwable cause) {
        super(cause);
    }
	
	public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
