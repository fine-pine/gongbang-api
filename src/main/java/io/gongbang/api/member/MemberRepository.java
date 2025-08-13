package io.gongbang.api.member;

import io.gongbang.api.member.model.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {
    boolean existsByEmail(String email);
    Optional<Member> findByEmail(String email);
    default Member findByEmailOrThrow(String email) {
        return findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("user not found with email: " + email));
    }
}
