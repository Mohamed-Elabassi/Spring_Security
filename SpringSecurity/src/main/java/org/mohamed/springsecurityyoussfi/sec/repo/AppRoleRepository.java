package org.mohamed.springsecurityyoussfi.sec.repo;


import org.mohamed.springsecurityyoussfi.sec.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AppRoleRepository  extends JpaRepository<AppRole,Long> {

    AppRole findAppRoleByRoleName(String roleName);
}
