package io.github.gandrade.security.openid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.Map;

@RestController
public class MainController {


    private OAuth2AuthorizedClientService auth2AuthorizedClientService;

    @Autowired
    public MainController(OAuth2AuthorizedClientService auth2AuthorizedClientService) {
        this.auth2AuthorizedClientService = auth2AuthorizedClientService;
    }

    @GetMapping("/")
    String home(Model model, OAuth2AuthenticationToken authenticationToken) {
        OAuth2AuthorizedClient authorizedClient = this.getAuthorizedClient(authenticationToken);
        model.addAttribute("userName", authenticationToken.getName());
        model.addAttribute("clientName", authorizedClient.getClientRegistration().getClientName());
        return "index";
    }

    @GetMapping("/userinfo")
    public String userinfo(Model model, OAuth2AuthenticationToken authenticationToken) {
        OAuth2AuthorizedClient authorizedClient = this.getAuthorizedClient(authenticationToken);
        Map userAttributes = Collections.emptyMap();
        String userInfoEndpointUri = authorizedClient.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri();
        if (!StringUtils.isEmpty(userInfoEndpointUri)) {    // userInfoEndpointUri is optional for OIDC Clients
            userAttributes = WebClient.builder()
                    .filter(oauth2Credentials(authorizedClient)).build()
                    .get().uri(userInfoEndpointUri)
                    .retrieve()
                    .bodyToMono(Map.class).block();
        }
        model.addAttribute("userAttributes", userAttributes);
        return "userinfo";
    }

    @GetMapping("/logout")
    public String logout(Model model, OAuth2AuthenticationToken authenticationToken) {
        return "index";
    }


    private OAuth2AuthorizedClient getAuthorizedClient(OAuth2AuthenticationToken oAuth2AuthenticationToken) {
        return this.auth2AuthorizedClientService.loadAuthorizedClient(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId(), oAuth2AuthenticationToken.getName());
    }

    private ExchangeFilterFunction oauth2Credentials(OAuth2AuthorizedClient authorizedClient) {
        return ExchangeFilterFunction.ofRequestProcessor(
                clientRequest -> {
                    ClientRequest authorizedRequest = ClientRequest.from(clientRequest)
                            .header(HttpHeaders.AUTHORIZATION,
                                    "Bearer " + authorizedClient.getAccessToken().getTokenValue())
                            .build();
                    return Mono.just(authorizedRequest);
                });
    }


}
