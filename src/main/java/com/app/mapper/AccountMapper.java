package com.app.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.springframework.dao.DataAccessException;

import com.app.security.JwtUser;

@Mapper
public interface AccountMapper {
	
	public JwtUser selectByEmail(String email) throws DataAccessException;
	
	public void updateAccessDateByEmail(String email) throws DataAccessException;
	
}
