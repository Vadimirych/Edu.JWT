Attacks on JWT 
-------------
Source: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html

1. [None Hashing Algorithm](#1-none-hashing-algorithm)
2. [Token Sidejacking](#2-token-sidejacking)
3. [No Built-In Token Revocation by the User](#3-no-built-in-token-revocation-by-the-user)
4. [Token Information Disclosure](#4-token-information-disclosure)
5. [Token Storage on Client Side](#5-token-storage-on-client-side)
6. [Weak Token Secret](#6-weak-token-secret)


## 1. None Hashing Algorithm

**Links:**  
* https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/ 

**Desrcription**   
This attack occurs when an attacker alters the token and changes the hashing algorithm to indicate, through the none keyword, that the integrity of the token has already been verified. As explained in the link above some libraries treated tokens signed with the none algorithm as a valid token with a verified signature, so an attacker can alter the token claims and the modified token will still be trusted by the application

**How to prevent**  
1. use a JWT library that is not exposed to this vulnerability.
2. during token validation, explicitly request that the expected algorithm was used.

**Implementation Example**  
```java
// HMAC key - Block serialization and storage as String in JVM memory
private transient byte[] keyHMAC = ...;

...

//Create a verification context for the token requesting
//explicitly the use of the HMAC-256 hashing algorithm
JWTVerifier verifier = JWT.require(Algorithm.HMAC256(keyHMAC)).build();

//Verify the token, if the verification fail then a exception is thrown
DecodedJWT decodedToken = verifier.verify(token);
```

## 2. Token Sidejacking
**Links**  
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#SameSite_cookies
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
* https://googlechrome.github.io/samples/cookie-prefixes/
* https://gdpr.eu/

**Description**  
This attack occurs when a token has been intercepted/stolen by an attacker and they use it to gain access to the system using targeted user identity.

**How to Prevent**  
A way to prevent it is to add a "user context" in the token. A user context will be composed of the following information:

A random string that will be generated during the authentication phase. It will be sent to the client as an hardened cookie (flags: HttpOnly + Secure + SameSite + Max-Age + cookie prefixes). Avoid setting expires header so that the cookie is cleared when the browser is closed. Set Max-Age to a value smaller or equal to the value of JWT expiry, but never more.
A SHA256 hash of the random string will be stored in the token (instead of the raw value) in order to prevent any XSS issues allowing the attacker to read the random string value and setting the expected cookie.
IP addresses should not be used because there are some legitimate situations in which the IP address can change during the same session. For example, when an user accesses an application through their mobile device and the mobile operator changes during the exchange, then the IP address may (often) change. Moreover, using the IP address can potentially cause issues with European GDPR compliance.

During token validation, if the received token does not contain the right context (for example, if it has been replayed), then it must be rejected.

**Implementation Example - Code to create the token after successful authentication**

```java
// HMAC key - Block serialization and storage as String in JVM memory
private transient byte[] keyHMAC = ...;
// Random data generator
private SecureRandom secureRandom = new SecureRandom();

...

//Generate a random string that will constitute the fingerprint for this user
byte[] randomFgp = new byte[50];
secureRandom.nextBytes(randomFgp);
String userFingerprint = DatatypeConverter.printHexBinary(randomFgp);

//Add the fingerprint in a hardened cookie - Add cookie manually because
//SameSite attribute is not supported by javax.servlet.http.Cookie class
String fingerprintCookie = "__Secure-Fgp=" + userFingerprint
                           + "; SameSite=Strict; HttpOnly; Secure";
response.addHeader("Set-Cookie", fingerprintCookie);

//Compute a SHA256 hash of the fingerprint in order to store the
//fingerprint hash (instead of the raw value) in the token
//to prevent an XSS to be able to read the fingerprint and
//set the expected cookie itself
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] userFingerprintDigest = digest.digest(userFingerprint.getBytes("utf-8"));
String userFingerprintHash = DatatypeConverter.printHexBinary(userFingerprintDigest);

//Create the token with a validity of 15 minutes and client context (fingerprint) information
Calendar c = Calendar.getInstance();
Date now = c.getTime();
c.add(Calendar.MINUTE, 15);
Date expirationDate = c.getTime();
Map<String, Object> headerClaims = new HashMap<>();
headerClaims.put("typ", "JWT");
String token = JWT.create().withSubject(login)
   .withExpiresAt(expirationDate)
   .withIssuer(this.issuerID)
   .withIssuedAt(now)
   .withNotBefore(now)
   .withClaim("userFingerprint", userFingerprintHash)
   .withHeader(headerClaims)
   .sign(Algorithm.HMAC256(this.keyHMAC));
```

**Implementation Example - Code to validate the token**

```java
// HMAC key - Block serialization and storage as String in JVM memory
private transient byte[] keyHMAC = ...;

...

//Retrieve the user fingerprint from the dedicated cookie
String userFingerprint = null;
if (request.getCookies() != null && request.getCookies().length > 0) {
 List<Cookie> cookies = Arrays.stream(request.getCookies()).collect(Collectors.toList());
 Optional<Cookie> cookie = cookies.stream().filter(c -> "__Secure-Fgp"
                                            .equals(c.getName())).findFirst();
 if (cookie.isPresent()) {
   userFingerprint = cookie.get().getValue();
 }
}

//Compute a SHA256 hash of the received fingerprint in cookie in order to compare
//it to the fingerprint hash stored in the token
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] userFingerprintDigest = digest.digest(userFingerprint.getBytes("utf-8"));
String userFingerprintHash = DatatypeConverter.printHexBinary(userFingerprintDigest);

//Create a verification context for the token
JWTVerifier verifier = JWT.require(Algorithm.HMAC256(keyHMAC))
                              .withIssuer(issuerID)
                              .withClaim("userFingerprint", userFingerprintHash)
                              .build();

//Verify the token, if the verification fail then an exception is thrown
DecodedJWT decodedToken = verifier.verify(token);
```

## 3. No Built-In Token Revocation by the User

**Description**  
This problem is inherent to JWT because a token only becomes invalid when it expires. The user has no built-in feature to explicitly revoke the validity of a token. This means that if it is stolen, a user cannot revoke the token itself thereby blocking the attacker.

**How to Prevent**  
Since JWTs are stateless, There is no session maintained on the server(s) serving client requests. As such, there is no session to invalidate on the server side. A well implemented Token Sidejacking solution (as explained above) should alleviate the need for maintaining denylist on server side. This is because a hardened cookie used in the Token Sidejacking can be considered as secure as a session ID used in the traditional session system, and unless both the cookie and the JWT are intercepted/stolen, the JWT is unusable. A logout can thus be 'simulated' by clearing the JWT from session storage. If the user chooses to close the browser instead, then both the cookie and sessionStorage are cleared automatically.

Another way to protect against this is to implement a token denylist that will be used to mimic the "logout" feature that exists with traditional session management system.

The denylist will keep a digest (SHA-256 encoded in HEX) of the token with a revocation date. This entry must endure at least until the expiration of the token.

When the user wants to "logout" then it call a dedicated service that will add the provided user token to the denylist resulting in an immediate invalidation of the token for further usage in the application.


**Implementation Example - Block List Storage**  
A database table with the following structure will be used as the central denylist storage.

```java
create table if not exists revoked_token(jwt_token_digest varchar(255) primary key,
revocation_date timestamp default now());
```

**Implementation example - Token Revocation Management**  

```java
/**
* Handle the revocation of the token (logout).
* Use a DB in order to allow multiple instances to check for revoked token
* and allow cleanup at centralized DB level.
*/
public class TokenRevoker {

 /** DB Connection */
 @Resource("jdbc/storeDS")
 private DataSource storeDS;

 /**
  * Verify if a digest encoded in HEX of the ciphered token is present
  * in the revocation table
  *
  * @param jwtInHex Token encoded in HEX
  * @return Presence flag
  * @throws Exception If any issue occur during communication with DB
  */
 public boolean isTokenRevoked(String jwtInHex) throws Exception {
     boolean tokenIsPresent = false;
     if (jwtInHex != null && !jwtInHex.trim().isEmpty()) {
         //Decode the ciphered token
         byte[] cipheredToken = DatatypeConverter.parseHexBinary(jwtInHex);

         //Compute a SHA256 of the ciphered token
         MessageDigest digest = MessageDigest.getInstance("SHA-256");
         byte[] cipheredTokenDigest = digest.digest(cipheredToken);
         String jwtTokenDigestInHex = DatatypeConverter.printHexBinary(cipheredTokenDigest);

         //Search token digest in HEX in DB
         try (Connection con = this.storeDS.getConnection()) {
             String query = "select jwt_token_digest from revoked_token where jwt_token_digest = ?";
             try (PreparedStatement pStatement = con.prepareStatement(query)) {
                 pStatement.setString(1, jwtTokenDigestInHex);
                 try (ResultSet rSet = pStatement.executeQuery()) {
                     tokenIsPresent = rSet.next();
                 }
             }
         }
     }

     return tokenIsPresent;
 }


 /**
  * Add a digest encoded in HEX of the ciphered token to the revocation token table
  *
  * @param jwtInHex Token encoded in HEX
  * @throws Exception If any issue occur during communication with DB
  */
 public void revokeToken(String jwtInHex) throws Exception {
     if (jwtInHex != null && !jwtInHex.trim().isEmpty()) {
         //Decode the ciphered token
         byte[] cipheredToken = DatatypeConverter.parseHexBinary(jwtInHex);

         //Compute a SHA256 of the ciphered token
         MessageDigest digest = MessageDigest.getInstance("SHA-256");
         byte[] cipheredTokenDigest = digest.digest(cipheredToken);
         String jwtTokenDigestInHex = DatatypeConverter.printHexBinary(cipheredTokenDigest);

         //Check if the token digest in HEX is already in the DB and add it if it is absent
         if (!this.isTokenRevoked(jwtInHex)) {
             try (Connection con = this.storeDS.getConnection()) {
                 String query = "insert into revoked_token(jwt_token_digest) values(?)";
                 int insertedRecordCount;
                 try (PreparedStatement pStatement = con.prepareStatement(query)) {
                     pStatement.setString(1, jwtTokenDigestInHex);
                     insertedRecordCount = pStatement.executeUpdate();
                 }
                 if (insertedRecordCount != 1) {
                     throw new IllegalStateException("Number of inserted record is invalid," +
                     " 1 expected but is " + insertedRecordCount);
                 }
             }
         }

     }
 }
 ```

 ## 4. Token Information Disclosure
**Links**  
* https://tools.ietf.org/html/rfc5116
* https://github.com/google/tink/blob/master/docs/PRIMITIVES.md#deterministic-authenticated-encryption-with-associated-data
* https://github.com/google/tink



 **Description**  
 This attack occurs when an attacker has access to a token (or a set of tokens) and extracts information stored in it (the contents of JWTs are base64 encoded, but is not encrypted by default) in order to obtain information about the system. Information can be for example the security roles, login format

**How to prevent**  
 A way to protect against this attack is to cipher the token using, for example, a symmetric algorithm.

It's also important to protect the ciphered data against attack like Padding Oracle or any other attack using cryptanalysis.

In order to achieve all these goals, the AES-GCM algorithm is used which provides Authenticated Encryption with Associated Data.

AEAD primitive (Authenticated Encryption with Associated Data) provides functionality of symmetric
authenticated encryption.

Implementations of this primitive are secure against adaptive chosen ciphertext attacks.

When encrypting a plaintext one can optionally provide associated data that should be authenticated
but not encrypted.

That is, the encryption with associated data ensures authenticity (ie. who the sender is) and
integrity (ie. data has not been tampered with) of that data, but not its secrecy.

See RFC5116: https://tools.ietf.org/html/rfc5116

**Note:**

Here ciphering is added mainly to hide internal information but it's very important to remember that the first protection against tampering of the JWT is the signature. So, the token signature and its verification must be always in place.


**Implementation Example - Token Ciphering**  
Code in charge of managing the ciphering. Google Tink dedicated crypto library is used to handle ciphering operations in order to use built-in best practices provided by this library.

```java
/**
 * Handle ciphering and deciphering of the token using AES-GCM.
 *
 * @see "https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md"
 */
public class TokenCipher {

    /**
     * Constructor - Register AEAD configuration
     *
     * @throws Exception If any issue occur during AEAD configuration registration
     */
    public TokenCipher() throws Exception {
        AeadConfig.register();
    }

    /**
     * Cipher a JWT
     *
     * @param jwt          Token to cipher
     * @param keysetHandle Pointer to the keyset handle
     * @return The ciphered version of the token encoded in HEX
     * @throws Exception If any issue occur during token ciphering operation
     */
    public String cipherToken(String jwt, KeysetHandle keysetHandle) throws Exception {
        //Verify parameters
        if (jwt == null || jwt.isEmpty() || keysetHandle == null) {
            throw new IllegalArgumentException("Both parameters must be specified!");
        }

        //Get the primitive
        Aead aead = AeadFactory.getPrimitive(keysetHandle);

        //Cipher the token
        byte[] cipheredToken = aead.encrypt(jwt.getBytes(), null);

        return DatatypeConverter.printHexBinary(cipheredToken);
    }

    /**
     * Decipher a JWT
     *
     * @param jwtInHex     Token to decipher encoded in HEX
     * @param keysetHandle Pointer to the keyset handle
     * @return The token in clear text
     * @throws Exception If any issue occur during token deciphering operation
     */
    public String decipherToken(String jwtInHex, KeysetHandle keysetHandle) throws Exception {
        //Verify parameters
        if (jwtInHex == null || jwtInHex.isEmpty() || keysetHandle == null) {
            throw new IllegalArgumentException("Both parameters must be specified !");
        }

        //Decode the ciphered token
        byte[] cipheredToken = DatatypeConverter.parseHexBinary(jwtInHex);

        //Get the primitive
        Aead aead = AeadFactory.getPrimitive(keysetHandle);

        //Decipher the token
        byte[] decipheredToken = aead.decrypt(cipheredToken, null);

        return new String(decipheredToken);
    }
}
```

**Implementation Example - Creation / Validation of the Token**  
Use the token ciphering handler during the creation and the validation of the token.

Load keys (ciphering key was generated and stored using Google Tink) and setup cipher.
```java
//Load keys from configuration text/json files in order to avoid to storing keys as a String in JVM memory
private transient byte[] keyHMAC = Files.readAllBytes(Paths.get("src", "main", "conf", "key-hmac.txt"));
private transient KeysetHandle keyCiphering = CleartextKeysetHandle.read(JsonKeysetReader.withFile(
Paths.get("src", "main", "conf", "key-ciphering.json").toFile()));

...

//Init token ciphering handler
TokenCipher tokenCipher = new TokenCipher();
```

**Implementation Example - Token creation**  

```java
//Generate the JWT token using the JWT API...
//Cipher the token (String JSON representation)
String cipheredToken = tokenCipher.cipherToken(token, this.keyCiphering);
//Send the ciphered token encoded in HEX to the client in HTTP response...
```

**Implementation Example - Token validation**  
```java
//Retrieve the ciphered token encoded in HEX from the HTTP request...
//Decipher the token
String token = tokenCipher.decipherToken(cipheredToken, this.keyCiphering);
//Verify the token using the JWT API...
//Verify access...
```

## 5. Token Storage on Client Side

**Description**  

This occurs when an application stores the token in a manner exhibiting the following behavior:

1. Automatically sent by the browser (Cookie storage).
2. Retrieved even if the browser is restarted (Use of browser localStorage container).
3. Retrieved in case of XSS issue (Cookie accessible to JavaScript code or Token stored in browser local/session storage).

**How to Prevent**  

1. Store the token using the browser sessionStorage container, or use JavaScript closures with private variables
2. Add it as a Bearer HTTP Authentication header with JavaScript when calling services.
3. Add fingerprint information to the token.

By storing the token in browser sessionStorage container it exposes the token to being stolen through a XSS attack. However, fingerprints added to the token prevent reuse of the stolen token by the attacker on their machine. To close a maximum of exploitation surfaces for an attacker, add a browser Content Security Policy to harden the execution context.

An alternative to storing token in browser sessionStorage is to use JavaScript private variable or Closures. In this, access to all web requests are routed through a JavaScript module that encapsulates the token in a private variable which can not be accessed other than from within the module.

**Note:**

The remaining case is when an attacker uses the user's browsing context as a proxy to use the target application through the legitimate user but the Content Security Policy can prevent communication with non expected domains.
It's also possible to implement the authentication service in a way that the token is issued within a hardened cookie, but in this case, protection against a Cross-Site Request Forgery attack must be implemented.

**Implementation Example**  

JavaScript code to store the token after authentication.

```JavaScript
/* Handle request for JWT token and local storage*/
function authenticate() {
    const login = $("#login").val();
    const postData = "login=" + encodeURIComponent(login) + "&password=test";

    $.post("/services/authenticate", postData, function (data) {
        if (data.status == "Authentication successful!") {
            ...
            sessionStorage.setItem("token", data.token);
        }
        else {
            ...
            sessionStorage.removeItem("token");
        }
    })
    .fail(function (jqXHR, textStatus, error) {
        ...
        sessionStorage.removeItem("token");
    });
}
```

JavaScript code to add the token as a Bearer HTTP Authentication header when calling a service, for example a service to validate token here.

```JavaScript
/* Handle request for JWT token validation */
function validateToken() {
    var token = sessionStorage.getItem("token");

    if (token == undefined || token == "") {
        $("#infoZone").removeClass();
        $("#infoZone").addClass("alert alert-warning");
        $("#infoZone").text("Obtain a JWT token first :)");
        return;
    }

    $.ajax({
        url: "/services/validate",
        type: "POST",
        beforeSend: function (xhr) {
            xhr.setRequestHeader("Authorization", "bearer " + token);
        },
        success: function (data) {
            ...
        },
        error: function (jqXHR, textStatus, error) {
            ...
        },
    });
}
```


JavaScript code to implement closures with private variables:

```JavaScript
function myFetchModule() {
    // Protect the original 'fetch' from getting overwritten via XSS
    const fetch = window.fetch;

    const authOrigins = ["https://yourorigin", "http://localhost"];
    let token = '';

    this.setToken = (value) => {
        token = value
    }

    this.fetch = (resource, options) => {
        let req = new Request(resource, options);
        destOrigin = new URL(req.url).origin;
        if (token && authOrigins.includes(destOrigin)) {
            req.headers.set('Authorization', token);
        }
        return fetch(req)
    }
}

...

// usage:
const myFetch = new myFetchModule()

function login() {
  fetch("/api/login")
      .then((res) => {
          if (res.status == 200) {
              return res.json()
          } else {
              throw Error(res.statusText)
          }
      })
      .then(data => {
          myFetch.setToken(data.token)
          console.log("Token received and stored.")
      })
      .catch(console.error)
}

...

// after login, subsequent api calls:
function makeRequest() {
    myFetch.fetch("/api/hello", {headers: {"MyHeader": "foobar"}})
        .then((res) => {
            if (res.status == 200) {
                return res.text()
            } else {
                throw Error(res.statusText)
            }
        }).then(responseText => console.log("helloResponse", responseText))
        .catch(console.error)
}
```

## 6. Weak Token Secret

**Description**

When the token is protected using an HMAC based algorithm, the security of the token is entirely dependent on the strength of the secret used with the HMAC. If an attacker can obtain a valid JWT, they can then carry out an offline attack and attempt to crack the secret using tools such as John the Ripper or Hashcat.

If they are successful, they would then be able to modify the token and re-sign it with the key they had obtained. This could let them escalate their privileges, compromise other users' accounts, or perform other actions depending on the contents of the JWT.

There are a number of guides that document this process in greater detail.

**How to Prevent**  
The simplest way to prevent this attack is to ensure that the secret used to sign the JWTs is strong and unique, in order to make it harder for an attacker to crack. As this secret would never need to be typed by a human, it should be at least 64 characters, and generated using a secure source of randomness.

Alternatively, consider the use of tokens that are signed with RSA rather than using an HMAC and secret key.

**Further Reading**  

* [{JWT}.{Attack}.Playbook](https://github.com/ticarpi/jwt_tool/wiki) - A project documents the known attacks and potential security vulnerabilities and misconfigurations of JSON Web Tokens.
* [JWT Best Practices Internet Draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-bcp/)