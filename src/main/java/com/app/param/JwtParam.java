package com.app.param;

import java.io.Serializable;

import javax.validation.constraints.NotEmpty;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JwtParam implements Serializable {

    private static final long serialVersionUID = -8445943548965154778L;

    @NotEmpty
    private String email;
    
    @NotEmpty
    private String password;

}
