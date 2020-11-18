package org.t246osslab.easybuggy.vulnerabilities;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.directory.server.core.filtering.EntryFilteringCursor;
import org.apache.directory.shared.ldap.filter.ExprNode;
import org.apache.directory.shared.ldap.filter.FilterParser;
import org.apache.directory.shared.ldap.filter.SearchScope;
import org.apache.directory.shared.ldap.message.AliasDerefMode;
import org.apache.directory.shared.ldap.name.LdapDN;
import org.t246osslab.easybuggy.core.dao.EmbeddedADS;
import org.t246osslab.easybuggy.core.servlets.DefaultLoginServlet;

@SuppressWarnings("serial")
@WebServlet(urlPatterns = { "/ldapijc/login" })
public class LDAPInjectionServlet extends DefaultLoginServlet {

    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        req.setAttribute("login.page.note", "msg.note.ldap.injection");
        super.doGet(req, res);
    }
    
    @Override
    protected boolean authUser(String uid, String password) {

        if (StringUtils.isBlank(uid) || uid.length() < 5 || StringUtils.isBlank(password) || password.length() < 8) {
            return false;
        }
        
        ExprNode filter;
        EntryFilteringCursor cursor = null;
        try {
            filter = FilterParser.parse("(&(uid=" + escapeLDAPSearchFilter(uid).trim() + ")(userPassword=" + escapeLDAPSearchFilter(password).trim() + "))");
            cursor = EmbeddedADS.getAdminSession().search(new LdapDN("ou=people,dc=t246osslab,dc=org"),
                    SearchScope.SUBTREE, filter, AliasDerefMode.NEVER_DEREF_ALIASES, null);
            if (cursor.available()) {
                return true;
            }
        } catch (Exception e) {
            log.error("Exception occurs: ", e);
        } finally {
            if (cursor != null) {
                try {
                    cursor.close();
                } catch (Exception e) {
                    log.error("Exception occurs: ", e);
                }
            }
        }
        return false;
    }
    public static final String escapeLDAPSearchFilter(String filter) 
    { 
        // If using JDK >= 1.5 consider using StringBuilder 
        StringBuffer sb = new StringBuffer();  
      
        for (int i = 0; i < filter.length(); i++) { 
            char curChar = filter.charAt(i); 
            switch (curChar) { 
            case '\\': 
                sb.append("\\5c"); 
                break; 
            case '*': 
                sb.append("\\2a"); 
                break; 
            case '(': 
                sb.append("\\28"); 
                break; 
            case ')': 
                sb.append("\\29"); 
                break; 
            case '\u0000': 
                sb.append("\\00"); 
                break; 
            default: 
                sb.append(curChar); 
            } 
        } 
        return sb.toString(); 
    } 
}
