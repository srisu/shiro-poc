package com.sri.demo;

import com.gofrugal.smart.api.multitenant.Tenant;
import org.apache.shiro.authc.UsernamePasswordToken;

public class TenantAuthenticationToken extends UsernamePasswordToken {

    private final Tenant tenant;

    public TenantAuthenticationToken(final String username, final String password, final boolean rememberMe, final String host, final Tenant tenant) {
        super(username, password, rememberMe, host);
        this.tenant = tenant;
    }

    public Tenant getTenant() {
        return tenant;
    }
}
