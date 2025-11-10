package io.jauth.auth.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * 获取请求和响应
 */
public class RequestContextUtil {


    /**
     * Get the current HTTP servlet request from Spring's RequestContextHolder.
     *
     * @return the current HTTP servlet request
     */
    public static HttpServletRequest getCurrentRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getRequest() : null;
    }

    /**
     * Get the current HTTP servlet response from Spring's RequestContextHolder.
     *
     * @return the current HTTP servlet response
     */
    public static HttpServletResponse getCurrentResponse() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getResponse() : null;
    }
}
