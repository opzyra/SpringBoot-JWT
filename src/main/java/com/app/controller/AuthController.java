package com.app.controller;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.app.param.JwtParam;
import com.app.security.JwtTokenUtil;
import com.app.security.JwtUser;
import com.app.service.JwtUserDetailsService;

@RestController
@RequestMapping("/auth")
public class AuthController {

	private final String TOKEN_HEADER = "Authorization";
	
    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private JwtUserDetailsService userDetailsService;
    
    @PostMapping(value = "/token")
    public ResponseEntity<?> createAuthenticationToken(@Valid @RequestBody JwtParam param) {

        String email = param.getEmail();
        String password = param.getPassword();
        
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
        } catch (DisabledException e) {
            throw new DisabledException("User is disabled");
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("Bad credentials");
        }

        userDetailsService.updateAccessLastDate(email);
        
        // Reload password post-security so we can generate the token
        final UserDetails userDetails = userDetailsService.loadUserByUsername(email);
        final String token = jwtTokenUtil.generateToken(userDetails);
        
        Map<String, String> out = new HashMap<>();
        out.put("token", token);
        
        // Return the token
        return ResponseEntity.ok(out);
    }
    
    @GetMapping(value = "/refresh")
    public ResponseEntity<?> refreshAndGetAuthenticationToken(HttpServletRequest request) {
        String authToken = request.getHeader(TOKEN_HEADER);
        final String token = authToken.substring(7);
        String email = jwtTokenUtil.getEmailFromToken(token);
        JwtUser user = (JwtUser) userDetailsService.loadUserByUsername(email);

        if (jwtTokenUtil.canTokenBeRefreshed(token, user)) {
            String refreshedToken = jwtTokenUtil.refreshToken(token);
            Map<String, String> out = new HashMap<>();
            out.put("token", refreshedToken);
            
            return ResponseEntity.ok(out);
        } else {
            return ResponseEntity.badRequest().body(null);
        }
    }

    // @PreAuthorize("hasRole('USER')")
}
