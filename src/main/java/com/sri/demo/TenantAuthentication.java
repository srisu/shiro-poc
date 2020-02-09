package com.sri.demo;

import com.gofrugal.smart.api.multitenant.Tenant;
import com.gofrugal.smart.api.util.APIUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.logging.*;

public class TenantAuthentication extends FormAuthenticationFilter {

    public static final String REQUEST_ATTRIBUTE_IS_USERTOKEN = "IS_USER_TOKEN";
    private static final Logger LOGGER = Logger.getLogger("TenantJdbcRealm.class");
    @Override
    protected AuthenticationToken createToken(final ServletRequest request, final ServletResponse response) {
        final HttpServletRequest hreq = (HttpServletRequest) request;
        final String username = getUsername(request);
        final String password = getPassword(request);
        final boolean rememberMe = isRememberMe(request);
        final String host = APIUtils.getHost(hreq);
        final Tenant tenant = APIUtils.getTenant(hreq);
        LOGGER.log(Level.INFO,"inside auth method");
        System.out.println("inside my filter");
        //System.out.println("inside auth");
        return createToken(username, password, rememberMe, host, tenant);
    }

    /**
     * Returns the authentication token with Tenant
     * @param username - String
     * @param password - String
     * @param rememberMe - boolean
     * @param host - String
     * @param tenant - Tenant
     * @return AuthenticationToken
     */
    private AuthenticationToken createToken(final String username, final String password, final boolean rememberMe, final String host, final Tenant tenant){
        return new TenantAuthenticationToken(username,password,rememberMe,host,tenant);
    }

    @Override
    protected boolean onLoginSuccess(final AuthenticationToken token,
                                     final Subject subject,
                                     final ServletRequest request,
                                     final ServletResponse response) throws Exception {
        LOGGER.log(Level.INFO,"inside login success");
        // System.out.println("sucess");
        final String username = super.getUsername(request);
        subject.getSession().setAttribute(APIUtils.REQUEST_ATTRIBUTE_LOGINID, username);
        subject.getSession().setAttribute(REQUEST_ATTRIBUTE_IS_USERTOKEN, "1");
        return super.onLoginSuccess(token,subject, request,response);
    }

    @Override
    protected boolean onLoginFailure(final AuthenticationToken token,
                                     final AuthenticationException e,
                                     final ServletRequest request,
                                     final ServletResponse response){
        LOGGER.log(Level.INFO,"inside logi failure");
        //System.out.println("failure");
        final HttpServletResponse hres = (HttpServletResponse) response;
        hres.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        return false;
    }
}

