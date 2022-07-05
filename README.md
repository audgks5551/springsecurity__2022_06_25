# 2022.06.25

## 주의 사항

- spring security 구현 방식이 변동
    - `WebSecurityConfigurerAdapter` => `WebSecurityConfiguration`
    - 상속이 아니라 빈 구성을 통해 보안 설정함
    - `WebSecurityConfiguration`는 `proxyBeanMethods를 false`로 주어 매번 객체가 생성되게 되어있다.
    ```java
    @Configuration(
      proxyBeanMethods = false
    )
    public class WebSecurityConfiguration implements ImportAware, BeanClassLoaderAware {}  
    ```
    - `ImportAware`은 @Configuration안에 구성된 빈을 가져와 빈을 구성한다. 
    - `BeanClassLoaderAware`는 빈 초기화 콜백 전에 `void setBeanClassLoader(ClassLoader classLoader)`를 호출한다.

## 알아야할 사항

- 기본적으로 필터가 11개가 구성이 된다.
```java
@Configuration
public class SecurityConfiguration {

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    http
            .authorizeRequests()
            .anyRequest().authenticated();

    return http.build();
  }
}
```
- 위의 처럼 생성시 `FilterSecurityInterceptor`가 필터에 추가되어 인가 정책을 적용한다.

```java
@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .formLogin();

        return http.build();
    }
}
```
- 위의 처럼 생성시 `UsernamePasswordAuthenticationFilter`, `DefaultLoginPageGeneratingFilter`, `DefaultLogoutPageGeneratingFilter`가 필터에 추가되어 인증 정책을 적용한다.


# 2022.06.26

## 알아야할 사항
```java
@Configuration
public class SecurityConfiguration {

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
            .formLogin() // form login 방식 사용
            .loginPage("/loginPage") // loginPage.html 작성
            .defaultSuccessUrl("/successUrl") // 성공 URL
            .failureUrl("/failUrl") // 실패 URL
            .usernameParameter("userId") // form input username name
            .passwordParameter("passwd") // form input password name
            .loginProcessingUrl("/login_proc") // form action URL
            .successHandler(new AuthenticationSuccessHandler() { // 로그인이 성공했을 때
              @Override
              public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                System.out.println("authentication: " + authentication.getName());
                response.sendRedirect("/success");
              }
            })
            .failureHandler(new AuthenticationFailureHandler() { // 로그인이 실패했을 때
              @Override
              public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                System.out.println("exception: " + exception.getMessage());
                response.sendRedirect("/fail");
              }
            })
            .permitAll(); // 로그인 페이지는 로그인 되지 않아도 들어올 수 있어야 되기 때문에 모두 인증 허용

    return http.build();
  }
}
```
 - `.loginPage("/loginPage")`가 작동이 되었을 때 `.defaultSuccessUrl("/successUrl")`와 `.failureUrl("/failUrl")`가 동작함
 - 아래의 5가지는 `.loginPage("/loginPage")`가 활성화되지 않아도 작동
    ```
    .usernameParameter()
    .passwordParameter()
    .loginProcessingUrl()
    .successHandler()
    .failureHandler()
    ```
 - `.loginPage("/loginPage")`가 작동되지 않았을 때 기본적으로 제공하는 `DefaultLoginPageGeneratingFilter`, `DefaultLogoutPageGeneratingFilter`가 추가되어 동작
 - `.loginPage("/loginPage")`가 작동되었을 때 `UsernamePasswordAuthenticationFilter`만 추가되어 동작

# 2022.06.27

## 알아야할 사항
 - `UsernamePasswordAuthenticationFilter`필터 과정
   1. `AbstractAuthenticationProcessingFilter` doFilter가 실행이 되어 아래와 같이 `.loginProcessingUrl("/login_proc")`에서 등록한 URL과 맞는지 검사하고 필터 로직 수행, 아니면 다음 필터로 간다
      ```
      if (!requiresAuthentication(request, response)) {
                chain.doFilter(request, response);
                return;
      }
      ```
   2. `AbstractAuthenticationProcessingFilter`의 doFilter에서 `Authentication authenticationResult = attemptAuthentication(request, response);`가 실행되어 인증을 시도한다.
   3. `attemptAuthentication`함수가 실행될 떄 `UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(username, password);`로직이 수행되어 인증되지 않은 `Authentication(=UsernamePasswordAuthenticationToken)` 발급
   4. 인증되지 않은 `Authentication(=UsernamePasswordAuthenticationToken)`을 `this.getAuthenticationManager().authenticate(authRequest);` 로직처럼 `AuthenticationManager`에게 인증을 위임한다.
      > `AuthenticationManager`의 구현체는 `ProviderManager`이다
   5. `ProviderManager`에서 `authenticate`이 수행되어 `AuthenticationProvider`의 구현체인 `DaoAuthenticationProvider`를 통해 아이디, 비밀번호를 통해 회원이 맞는지 검사하고 `Authentication`을 반환, 아니면 예외 발생 
   6. 반환된 `Authentication`를 통해  `successfulAuthentication(request, response, chain, authenticationResult);` 로직을 통해 `SecurityContext`에 `Authentication`을 저장하고 `successHandler` 작동 

# 2022.06.28

## 타임리프 설정
 - 의존성 추가
    ```
    implementation 'org.springframework.boot:spring-boot-starter-thymeleaf:2.7.1'
    implementation 'nz.net.ultraq.thymeleaf:thymeleaf-layout-dialect:3.1.0'
    implementation 'org.thymeleaf.extras:thymeleaf-extras-springsecurity5'
    ```
## tailwind 설정 및 daisy ui 설정
 - 라이브러리 추가
    ```bash
    npm i --prefix . -D tailwindcss
    npx tailwindcss init
    npm i daisyui
    ```
 - `package.json` 스크립트 작성
    ```
    "scripts": {
        "css": "npx tailwindcss -i ./src/main/resources/static/css/tailwind.source.css -o ./src/main/resources/static/css/tailwind.output.css --watch"
      },
    ```
 - `tailwind.config.js` 설정
    ```js
    module.exports = {
      mode: "jit",
      content: ["./src/main/resources/templates/**/*.{html,js}"],
      theme: {
        extend: {},
      },
      plugins: [require("daisyui")],
    }
    ```
 - 링크 참고
   - [https://tailwindcss.com/docs/installation](https://tailwindcss.com/docs/installation)
   - [https://daisyui.com/docs/install/](https://daisyui.com/docs/install/)

## spring boot devtools 설정
 - [https://shanepark.tistory.com/215](https://shanepark.tistory.com/215)


# 2022.06.29

## spring security documentation links
 - [https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter](https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter)
 - [https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/index.html](https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/index.html)
 - [https://www.codejava.net/frameworks/spring-boot/fix-websecurityconfigureradapter-deprecated](https://www.codejava.net/frameworks/spring-boot/fix-websecurityconfigureradapter-deprecated)

## 주의 사항
 - `.antMatchers("/message").hasRole("MANAGER")`는 `/message`만 적용
 - `.mvcMatchers("/message").hasRole("MANAGER")`는 `/message`와 `/message/` 등등 spring mvc 패턴이 적용
 - 결론은 `.mvcMatchers`이 더 안전함, 그러나 `.antMatchers`도 잘 사용하면 안전함 (예로는 `.antMatchers("/message/**").hasRole("MANAGER")`) 
 - [https://netmarble.engineering/spring-security-path-matching-inconsistency-cve-2016-5007/](https://netmarble.engineering/spring-security-path-matching-inconsistency-cve-2016-5007/)
 > 화이트리스트는 허용하는 조건 이외에는 모두 차단하는 접근 제어 방식입니다. 반대로, 블랙리스트는 차단하는 조건 이외에는 모두 허용하는 접근 제어 방식입니다.

## 알아야할 사항
```java
@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeRequests((authorizeRequests) -> authorizeRequests
                        .antMatchers("/").permitAll()
                        .antMatchers("/myPage").hasRole("USER")
                        .antMatchers("/message").hasRole("MANAGER")
                        .antMatchers("/config").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .formLogin()
                .permitAll();

        return http.build();
    }

    /**
     * 사용자 생성
     */
    @Bean
    public UserDetailsService users() {
        UserDetails user = User.builder()
                .username("user")
                .password("{noop}pass")
                .roles("USER")
                .build();

        UserDetails manager = User.builder()
                .username("manager")
                .password(passwordEncoder().encode("pass"))
                .roles("USER", "MANAGER")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("pass"))
                .roles("USER", "ADMIN", "MANAGER")
                .build();

        return new InMemoryUserDetailsManager(user, admin, manager);
    }

    /**
     * 패스워드 암호화
     *  - 인코딩시 BCryptPasswordEncoder 방식 사용
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * static 디렉터리의 하위 파일 목록은 무시
     *  - 보안 필터를 거치지 않는다
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
}
```
 - `PasswordEncoderFactories.createDelegatingPasswordEncoder().encode()`를 통해 암호화
 - `PasswordEncoderFactories.createDelegatingPasswordEncoder().match()`를 통해 복호화
    ```
    boolean matches = passwordEncoder().matches("pass", passwordEncoder().encode("pass"));
    System.out.println(matches); // true
    ```


# 2022.07.01

## 알아야할 사항

### 타임리프 layout 템플릿 만들기

 - `layouts/layout`
```html
<!DOCTYPE html>
    <html xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout">

    <head>
        <meta charset="UTF-8" />
        <link th:href="@{/css/tailwind.output.css}" rel="stylesheet">
    </head>

    <body class="flex flex-col min-h-screen">
        <header th:replace="layouts/header :: headerFragment"></header>

        <section layout:fragment="content" class="mt-16 flex-1">
            <div>내용</div>
        </section>

        <footer th:replace="layouts/footer :: footerFragment"></footer>
        
        <script src="http://code.jquery.com/jquery-latest.js"></script>
        <script layout:fragment="javascript" type="text/javascript"></script>
    </body>
</html>
```

 - `layouts/header`
```html
<!DOCTYPE html>
<html xmlns:sec="http://www.thymeleaf.org/extras/spring-security">

    <header th:fragment="headerFragment">
        <div>header</div>
    </header>

</html>
```

 - `layouts/footer`
```html
<!DOCTYPE html>
<html>

    <footer th:fragment="footerFragment">
        <div>footer</div>
    </footer>

</html>
```

 - template (이걸 들고 계속 페이지 생성하면 됨)
```html
<!DOCTYPE html>
<html xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout"
      layout:decorate="~{layouts/layout.html}">

    <head>
        <title>template</title>
    </head>
    
    <body>
        <section layout:fragment="content">
            <span>template</span>
        </section>
    </body>

</html>
```

 - form 
```html
<form th:action="@{/users}" method="POST" th:object="${userForm}"  class="card-body">

    <!-- username -->
    <label th:for="*{username}"></label>
    <input th:field="*{username}" type="text" placeholder="username"/>
    
    <!-- password -->
    <label th:for="*{password}"></label>
    <input th:field="*{password}" type="password" placeholder="password" />
    
    <!-- email -->
    <label th:for="*{email}"></label>
    <input th:field="*{email}" type="email" placeholder="email" />
    
    <!-- age -->
    <label th:for="*{age}"></label>
    <input th:field="*{age}" type="number" placeholder="age" />
    
    <!-- signup button -->
    <button type="submit">Sign Up</button>

</form>
```

# 2022.07.04

## 알아야할 사항
 
```java
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("UsernameNotFoundException"));

        return new AccountContext(account, Arrays.asList(new SimpleGrantedAuthority(account.getRole())));
    }
}
```
 - 유저의 아이디로 DB에서 유저가 있는지 확인한 후 AccountContext(=User) 객체 반환

```java
public class AccountContext extends User {

    private final Account account;

    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(), account.getPassword(), authorities);

        this.account = account;
    }
}
```
 - `User`를 상속받아 커스텀 유저 클래스 만들기

```java
@Controller
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    /**
     * 인증되지 않은 Authentication을 검증을 겨쳐 인증된 Authentication을 반환
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);

        if (!passwordEncoder.matches(password, accountContext.getPassword())) {
            throw new BadCredentialsException("BadCredentialsException");
        }

        return new UsernamePasswordAuthenticationToken(
                accountContext.getAccount(),
                null,
                accountContext.getAuthorities()
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
```
 - `AuthenticationProvider`는 마치 `controller`를 역핧을 하듯이 `service`를 불러오고 인증이 되면 인증이 된 `authentication`을 반환한다.

# 2022.07.05

## 알아야할 사항

```java
@GetMapping("/logout")
public String logout(HttpServletRequest request, HttpServletResponse response) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    if (authentication != null) {
        new SecurityContextLogoutHandler().logout(request, response, authentication);
    }

    return "redirect:/login";
}
```
 - `request`, `response`, `authentication`을 통해 로그아웃 처리

