package org.mohamed.springsecurityyoussfi.sec.repo;

import org.mohamed.springsecurityyoussfi.sec.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AppUserRepository extends JpaRepository<AppUser,Long> {

    AppUser  findUserByUsername(String username);

}
