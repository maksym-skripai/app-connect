package is.lako.appconnect.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import is.lako.appconnect.security.model.Credentials;
import is.lako.appconnect.security.model.SecurityProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@Slf4j
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    private SecurityService securityService;

    @Autowired
    private CookieService cookieUtils;

    @Autowired
    private SecurityProperties securityProps;

    @Autowired
    private UserService userService;

    @Autowired
    private FirebaseAuth firebaseAuth;

    @Autowired
    private ObjectMapper objectMapper;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        authorize(request);
        Object userObj = SecurityContextHolder.getContext().getAuthentication();
        User user = Objects.nonNull(userObj) ? (User) ((Authentication) userObj).getPrincipal() : null;

        if (Objects.nonNull(user) && !user.getActive()) {
            int errorCode = HttpStatus.FORBIDDEN.value();
            StatusBlock body = new StatusBlock(errorCode, "This user's account is inactive", StatusBlock.EventCode.EC_INACTIVE_ACCOUNT);

            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(errorCode);
            response.getWriter().write(objectMapper.writeValueAsString(body));
        } else {
            filterChain.doFilter(request, response);
        }
    }

    private void authorize(HttpServletRequest request) {
        String sessionCookieValue = null;
        FirebaseToken decodedToken = null;
        Credentials.CredentialType type = null;
        // Token verification
        boolean strictServerSessionEnabled = securityProps.getFirebaseProps().isEnableStrictServerSession();
        Cookie sessionCookie = cookieUtils.getCookie("session");
        String token = securityService.getBearerToken(request);
        try {
            if (sessionCookie != null) {
                sessionCookieValue = sessionCookie.getValue();
                decodedToken = firebaseAuth.verifySessionCookie(sessionCookieValue,
                        securityProps.getFirebaseProps().isEnableCheckSessionRevoked());
                type = CredentialType.SESSION;
            } else if (!strictServerSessionEnabled && token != null && !token.equals("null")
                    && !token.equalsIgnoreCase("undefined")) {
                decodedToken = firebaseAuth.verifyIdToken(token);
                type = CredentialType.ID_TOKEN;
            }
        } catch (FirebaseAuthException e) {
            log.error("Firebase Exception: Cannot verify token");
        }
        List<GrantedAuthority> authorities = new ArrayList<>();
        FirebaseUser firebaseUser = firebaseTokenToUserDto(decodedToken);

        if (firebaseUser != null) {

            User user;
            //create user if not exists
            if (!userService.isExists(firebaseUser.getUid())) {
                user = new User();
                user.setEmail(firebaseUser.getEmail());
                user.setPicture(firebaseUser.getPicture());
                user.setFirebaseUid(firebaseUser.getUid());
                user.setFirebaseUser(firebaseUser);
                user.setSignInProvider(firebaseUser.getSignInProvider().name());
                user.setLang("UA");
                user.setActive(true);
                user.setComplete(false);
                userService.save(user);
            } else {
                user = userService.getByFirebaseUid(firebaseUser.getUid());
            }

            decodedToken.getClaims().forEach((k, v) -> authorities.add(new SimpleGrantedAuthority(k)));
            // Set security context
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user,
                    new Credentials(type, decodedToken, token, sessionCookieValue), authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
    }

    private FirebaseUser firebaseTokenToUserDto(FirebaseToken decodedToken) {
        FirebaseUser user = null;
        if (decodedToken != null) {
            user = new FirebaseUser();
            user.setUid(decodedToken.getUid());
            user.setName(decodedToken.getName());
            user.setEmail(decodedToken.getEmail());
            user.setPicture(decodedToken.getPicture());
            user.setIssuer(decodedToken.getIssuer());
            user.setEmailVerified(decodedToken.isEmailVerified());
            String signInProvider = (String) ((ArrayMap<String, Object>) decodedToken.getClaims().get("firebase"))
                    .get("sign_in_provider");
            user.setSignInProvider(FirebaseUser.SignInProvider.get(signInProvider));
        }
        return user;
    }
}