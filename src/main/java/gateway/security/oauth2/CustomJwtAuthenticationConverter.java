package gateway.security.oauth2;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

public class CustomJwtAuthenticationConverter extends JwtAuthenticationConverter {

	// TODO this should be updated to work both with keycloak default and OKTA
	protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
		Map<String, Object> clientRoles = jwt.getClaimAsMap("resource_access");
		Stream<String> roles = clientRoles.entrySet().stream()
				.flatMap(c -> ((JSONArray) ((JSONObject) c.getValue()).get("roles")).stream()
						.map(r -> this.clientIdToprefix(c.getKey()) + r));

		Collection<GrantedAuthority> authorites = roles.map(SimpleGrantedAuthority::new).collect(Collectors.toList());

		Stream<String> realmRoles = ((JSONArray) jwt.getClaimAsMap("realm_access").get("roles")).stream()
				.map(r -> "" + r);

		authorites.addAll(realmRoles.map(SimpleGrantedAuthority::new).collect(Collectors.toList()));

		return authorites;
	}

	private String clientIdToprefix(String clientId) {
		if (clientId.equals("web_app")) {
			return "";
		}
		return clientId + "-";
	}
}
