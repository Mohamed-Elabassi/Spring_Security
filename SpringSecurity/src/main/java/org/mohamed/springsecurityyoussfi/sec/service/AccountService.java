package org.mohamed.springsecurityyoussfi.sec.service;


import org.mohamed.springsecurityyoussfi.sec.entities.AppRole;
import org.mohamed.springsecurityyoussfi.sec.entities.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username, String roleName);
    AppUser loadUserByUsername(String username);
    List<AppUser> ListUsers();
}
