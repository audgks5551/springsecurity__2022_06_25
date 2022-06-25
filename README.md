# 2022.06.25

## 문제점

- user 1개 (미해결)
- 권한 없음 (미해결)
- 보안시스템 없음 (미해결)

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

