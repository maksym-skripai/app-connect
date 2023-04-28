package is.lako.appconnect.security.model;

import lombok.Data;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;

@Data
public class FirebaseUser implements Serializable {
//	private static final long serialVersionUID = 4408418647685225829L;
	private String uid;
	private String name;
	private String email;
	private boolean isEmailVerified;
	private String issuer;
	private String picture;
	private SignInProvider signInProvider;

	public enum SignInProvider{
		GOOGLE("google.com"), EMAIL("password"), NONE("");

		private String key;

		SignInProvider(String key) {
			this.key = key;
		}

		public static SignInProvider get(String key) {
			List<SignInProvider> values = Arrays.asList(SignInProvider.values());
			return values.parallelStream()
					.filter(i -> i.key.equalsIgnoreCase(key))
					.findFirst()
					.orElse(SignInProvider.NONE);
		}
	}
}