const express = require("express");
const request = require("request");
const jwt = require("jsonwebtoken");
const jose = require("jose");
const bodyParser = require("body-parser");
const app = express();
const fs = require("fs");

const private_key = fs.readFileSync("./appleSignIn_private_key.p8");
const client_id = "com.nineyi.shop.s001993";

function generateClientSecret() {
  // Generate client secret
  let client_secret = jwt.sign(
    {
      iss: "CGDF3735PK", // Team ID, should store in server side
      sub: client_id, // Bundle ID, should store in server side
      aud: "https://appleid.apple.com", // Fix value
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60 * 60,
    },
    private_key,
    {
      algorithm: "ES256",
      header: {
        alg: "ES256",
        kid: "PCKF47G23B", // Key ID, should store in a safe place on server side
      },
    }
  );
  return client_secret;
}

app.use(bodyParser.json());

app.get("/", function (req, res) {
  console.log("in");
  res.send("hello");
});

app.post("/verify", function (req, res) {
  console.log(req.body);
  let code = req.body.social_info.identity_code;
  let token = req.body.social_info.social_access_token;
  const buffCode = Buffer.from(code);
  const asciiCode = buffCode.toString("ascii");
  const utf8Code = buffCode.toString("utf8");
  console.log(buffCode);
  console.log(asciiCode);

  // Fetch public key from Apple
  request("https://appleid.apple.com/auth/keys", function (
    error,
    response,
    body
  ) {
    let jwks = jose.JWKS.asKeyStore(JSON.parse(body));

    // JWS Verify
    if (jose.JWS.verify(token, jwks)) {
      console.log("ID Token has been Verified");
      let client_secret = generateClientSecret();

      // Request verification for apple api
      request.post(
        {
          url: "https://appleid.apple.com/auth/token",
          form: {
            client_id: client_id,
            client_secret: client_secret,
            code: code,
            grant_type: "authorization_code",
          },
        },
        function (err, response, body) {
          console.log("----verified-------", body);
          res.send(body);
        }
      );
    } else {
      console.log("Cannot Verified ID Token");
      res.send(400);
    }
  });
});

app.listen(3000, function () {
  console.log("Example app listening on port 3000!");
});
