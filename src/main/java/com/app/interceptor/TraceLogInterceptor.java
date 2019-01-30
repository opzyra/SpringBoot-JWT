package com.app.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import com.app.common.RequestProvider;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class TraceLogInterceptor extends HandlerInterceptorAdapter {

	private long executeTime;

	private final String COMMASPACE = ", ";
	
	private final String NULL = "null";
	
	private final String ANONYMOUS_USER = "anonymousUser";
	
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
			throws Exception {
		
		executeTime = System.currentTimeMillis();
		
		return super.preHandle(request, response, handler);
	}

	@Override
	public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
			ModelAndView modelAndView) throws Exception {
		
		// 문자열 객체 생성
		StringBuffer logMessage = new StringBuffer();
    	
		// 실행 시간
        logMessage.append(System.currentTimeMillis() - executeTime).append(COMMASPACE);
		
    	// 클라이언트 IP
    	String clientIp = RequestProvider.getClientIp(request);
    	
    	// 클라이언트 IP를 취득한 경우
    	if(clientIp != null) {
    		
    		// 로그에 기록
    		logMessage.append(clientIp).append(COMMASPACE);
    		
    	} else {
    		
    		logMessage.append(NULL).append(COMMASPACE);
    		
    	}
    	
        // 클라이언트 HTTP 요청 메소드
        logMessage.append(request.getMethod()).append(COMMASPACE);
        
        // 클라이언트 HTTP 접속 URL
        logMessage.append(request.getRequestURI()).append(COMMASPACE);
        
        // 유저 정보
	    Authentication securitySession = SecurityContextHolder.getContext().getAuthentication();
    	
    	if(securitySession != null) {
    		
    		// 사용자 아이디
    		logMessage.append(securitySession.getName()).append(COMMASPACE);
    		
    	} else {
    		
    		logMessage.append(ANONYMOUS_USER).append(COMMASPACE);
    		
    	}
        
    	// 마지막 콤마 잘라내기
        logMessage.delete(logMessage.length()-2, logMessage.length());
        
        // TraceLog 출력
        log.info(logMessage.toString());
		
		super.postHandle(request, response, handler, modelAndView);
	}

}
