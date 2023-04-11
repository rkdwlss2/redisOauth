package project.SangHyun.domain.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import project.SangHyun.advice.exception.*;
import project.SangHyun.config.security.jwt.JwtTokenProvider;
import project.SangHyun.domain.auth.AccessToken;
import project.SangHyun.domain.auth.Profile.ProfileDto;
import project.SangHyun.domain.dto.MemberLoginResponseDto;
import project.SangHyun.domain.dto.MemberRegisterResponseDto;
import project.SangHyun.domain.dto.TokenResponseDto;
import project.SangHyun.domain.entity.Member;
import project.SangHyun.domain.entity.RedisKey;
import project.SangHyun.domain.repository.MemberRepository;
import project.SangHyun.web.dto.EmailAuthRequestDto;
import project.SangHyun.web.dto.MemberLoginRequestDto;
import project.SangHyun.web.dto.MemberRegisterRequestDto;
import project.SangHyun.web.dto.ReIssueRequestDto;

import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class SignService {

    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;

    private final MemberRepository memberRepository;

    private final ProviderService providerService;
    private final EmailService emailService;

    private final RedisService redisService;


    /**
     * Dto로 들어온 값을 통해 회원가입을 진행
     * @param requestDto
     * @return
     */
    @Transactional
    public MemberRegisterResponseDto registerMember(MemberRegisterRequestDto requestDto) {
        validateDuplicated(requestDto.getEmail());
        String authToken = UUID.randomUUID().toString();
        redisService.setDataWithExpiration(RedisKey.EAUTH.getKey()+requestDto.getEmail(),authToken,60*5L);

        Member member = memberRepository.save(
                Member.builder()
                        .email(requestDto.getEmail())
                        .password(passwordEncoder.encode(requestDto.getPassword()))
                        .provider(null)
                        .emailAuth(false)
                        .build());

        emailService.send(requestDto.getEmail(), authToken);
        return MemberRegisterResponseDto.builder()
                .id(member.getId())
                .email(member.getEmail())
                .build();
    }

    public void validateDuplicated(String email) {
        if (memberRepository.findByEmail(email).isPresent())
            throw new MemberEmailAlreadyExistsException();
    }

    /**
     * 이메일 인증 성공
     * @param requestDto
     */
    @Transactional
    public void confirmEmail(EmailAuthRequestDto requestDto) {
        if (redisService.getData(RedisKey.EAUTH.getKey())+requestDto.getEmail()==null){
            throw new EmailAuthTokenNotFountException();
        }
        Member member = memberRepository.findByEmail(requestDto.getEmail()).orElseThrow(MemberNotFoundException::new);
        redisService.deleteData(RedisKey.EAUTH.getKey()+requestDto.getEmail());
        member.emailVerifiedSuccess();
    }

    /**
     * 로컬 로그인 구현
     * @param requestDto
     * @return
     */
    @Transactional
    public MemberLoginResponseDto loginMember(MemberLoginRequestDto requestDto) {
        Member member = memberRepository.findByEmail(requestDto.getEmail()).orElseThrow(MemberNotFoundException::new);
        if (!passwordEncoder.matches(requestDto.getPassword(), member.getPassword()))
            throw new LoginFailureException();
        if (!member.getEmailAuth())
            throw new EmailNotAuthenticatedException();

        String refreshToken = jwtTokenProvider.createRefreshToken();
        redisService.setDataWithExpiration(RedisKey.REGISTER.getKey()+member.getEmail(),refreshToken,JwtTokenProvider.refreshTokenValidTime);
        return new MemberLoginResponseDto(member.getId(),jwtTokenProvider.createToken(requestDto.getEmail()),refreshToken);
    }

    /**
     * 소셜 로그인 구현
     * @param code
     * @param provider
     * @return
     */
    @Transactional
    public MemberLoginResponseDto loginMemberByProvider(String code, String provider) {
        AccessToken accessToken = providerService.getAccessToken(code, provider);
        ProfileDto profile = providerService.getProfile(accessToken.getAccess_token(), provider);

        String refreshToken = jwtTokenProvider.createRefreshToken();
        redisService.setDataWithExpiration(RedisKey.REGISTER.getKey() +refreshToken,refreshToken,JwtTokenProvider.refreshTokenValidTime);

        Optional<Member> findMember = memberRepository.findByEmailAndProvider(profile.getEmail(), provider);
        if (findMember.isPresent()) {
            Member member = findMember.get();
            return new MemberLoginResponseDto(member.getId(), jwtTokenProvider.createToken(findMember.get().getEmail()), refreshToken);
        } else {
            Member saveMember = saveMember(profile, provider);
            return new MemberLoginResponseDto(saveMember.getId(), jwtTokenProvider.createToken(saveMember.getEmail()), refreshToken);
        }
    }

    private Member saveMember(ProfileDto profile, String provider) {
        Member member = Member.builder()
                .email(profile.getEmail())
                .password(null)
                .provider(provider)
                .build();
        Member saveMember = memberRepository.save(member);
        return saveMember;
    }

    /**
     * 토큰 재발행
     * @param requestDto
     * @return
     */
    @Transactional
    public TokenResponseDto reIssue(ReIssueRequestDto requestDto) {
        String findRefreshToken = redisService.getData(RedisKey.REGISTER.getKey()+requestDto.getEmail());
        if (findRefreshToken==null|| !findRefreshToken.equals(requestDto.getRefreshToken()))
            throw new InvalidRefreshTokenException();

        Member member = memberRepository.findByEmail(requestDto.getEmail()).orElseThrow(MemberNotFoundException::new);
        String accessToken = jwtTokenProvider.createToken(member.getEmail());
        String refreshToken = jwtTokenProvider.createRefreshToken();
        redisService.setDataWithExpiration(RedisKey.REGISTER.getKey()+member.getEmail(),refreshToken,JwtTokenProvider.refreshTokenValidTime);
        return new TokenResponseDto(accessToken, refreshToken);
    }

}
