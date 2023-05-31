package org.mohamed.springsecurityyoussfi.sec.controller;


import lombok.AllArgsConstructor;
import lombok.Data;
import org.mohamed.springsecurityyoussfi.sec.entities.AppRole;
import org.mohamed.springsecurityyoussfi.sec.entities.AppUser;
import org.mohamed.springsecurityyoussfi.sec.service.AccountService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@AllArgsConstructor
public class AccountRestController {

    private AccountService accountService;

    @GetMapping(path = "/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> getAllUsers() {
        return accountService.ListUsers();
    }

    @PostMapping(path = "/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser) {
        return accountService.addNewUser(appUser);
    }

    @PostMapping(path = "/roles")
    public AppRole saveRole(@RequestBody AppRole appRole) {
        return accountService.addNewRole(appRole);
    }

    @PostMapping(path = "/addRoleToUser")
    public void addRoleToUser(@RequestBody UserRoleForm userRoleForm) {
        accountService.addRoleToUser(userRoleForm.getUsername(), userRoleForm.getRoleName());
    }

}

@Data
class UserRoleForm {
    private String username;
    private String roleName;
}
