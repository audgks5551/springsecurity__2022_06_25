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

