package io.gongbang.api.member;

import io.gongbang.api.member.exception.UsernameAlreadyExistsException;
import io.gongbang.api.member.model.Member;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService implements UserDetailsService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    public Member signUp(SignUpDto dto) {
        if (memberRepository.existsByEmail(dto.email())) {
            throw new UsernameAlreadyExistsException("already exist email");
        }

        Member member = Member.createMember(
                dto.email(),
                passwordEncoder.encode(dto.password()),
                dto.nickname()
        );

        memberRepository.save(member);
        return member;
    }

    public void withdraw(String email) {
        Member member = memberRepository.findByEmailOrThrow(email);
        memberRepository.delete(member);
    }

    public void changePassword(Member member, String password) {
        member.setPassword(passwordEncoder.encode(password));
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return memberRepository.findByEmailOrThrow(email);
    }
}
