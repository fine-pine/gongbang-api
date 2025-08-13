package io.gongbang.api.member;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SignUpDto(
        @NotBlank(message = "이메일을 입력해주세요")
        @Email(message = "유효하지 않은 이메일입니다")
        String email,
        @NotBlank(message = "비밀번호를 입력해주세요")
        @Size(max = 30, message = "비밀번호는 최대 30글자 입니다")
        String password,
        @NotBlank(message = "닉네임을 입력해주세요")
        @Size(max = 30, message = "닉네임은 최대 30글자 입니다")
        String nickname
) {}
