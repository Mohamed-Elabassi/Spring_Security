package org.mohamed.springsecurityyoussfi.sec.service;


import lombok.AllArgsConstructor;
import org.mohamed.springsecurityyoussfi.sec.entities.AppRole;
import org.mohamed.springsecurityyoussfi.sec.entities.AppUser;
import org.mohamed.springsecurityyoussfi.sec.repo.AppRoleRepository;
import org.mohamed.springsecurityyoussfi.sec.repo.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;

@Service
@Transactional
@AllArgsConstructor
public class AccountServiceImpl implements AccountService {

    private AppUserRepository appUserRepository;
    private AppRoleRepository appRoleRepository;
    private PasswordEncoder passwordEncoder;

    @Override
    public AppUser addNewUser(AppUser appUser) {
        appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
        return appUserRepository.save(appUser);
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser appUser = appUserRepository.findUserByUsername(username);
        AppRole appRole = appRoleRepository.findAppRoleByRoleName(roleName);
        appUser.getRoles().add(appRole);
    }

    @Override
    public AppUser loadUserByUsername(String username) {
        return appUserRepository.findUserByUsername(username);
    }

    @Override
    public List<AppUser> ListUsers() {
        return appUserRepository.findAll();
    }
}
