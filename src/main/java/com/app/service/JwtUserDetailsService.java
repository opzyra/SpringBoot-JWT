package com.app.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.app.mapper.AccountMapper;
import com.app.security.JwtUser;

@Service
@Transactional
public class JwtUserDetailsService implements UserDetailsService {

    @Autowired
    private AccountMapper accountMapper;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        JwtUser user = accountMapper.selectByEmail(email);

        if (user == null) {
            throw new UsernameNotFoundException("No user found with email");
        } else {
            return user;
        }
    }
    
    public void updateAccessLastDate(String email) {
    	accountMapper.updateAccessDateByEmail(email);
    }
}
