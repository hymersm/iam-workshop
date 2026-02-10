import express from "express";
import session from "express-session";
import bodyParser from "body-parser";
import passport from "passport";
import fs from "fs";
import path from "path";
import { Strategy as SamlStrategy, Profile, PassportSamlConfig, VerifiedCallback, VerifyWithRequest } from "@node-saml/passport-saml";

const signingKey = fs.readFileSync(path.join(process.cwd(), "saml-certs/sp-signing.key"), "utf8");
const signingCert = fs.readFileSync(path.join(process.cwd(), "saml-certs/sp-signing.crt"), "utf8");

const decryptionKey = fs.readFileSync(path.join(process.cwd(), "saml-certs/sp-encryption.key"), "utf8");
const decryptionCert = fs.readFileSync(path.join(process.cwd(), "saml-certs/sp-encryption.crt"), "utf8");

const idpCert = fs.readFileSync(path.join(process.cwd(), "saml-certs/idp.crt"), "utf8");

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));

app.use(
  session({
    secret: "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false },
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user: any, done) => done(null, user));
passport.deserializeUser((user: any, done) => done(null, user));

const passportSamlConfig: PassportSamlConfig = {
  callbackUrl: "http://localhost:3000/login/callback",
  issuer: "http://localhost:3000/metadata",
  entryPoint: "http://localhost:18080/simplesaml/saml2/idp/SSOService.php",
  idpCert: idpCert,
  privateKey: signingKey,
  signatureAlgorithm: "sha256",
  digestAlgorithm: "sha256",
  decryptionPvk: decryptionKey,
  disableRequestedAuthnContext: true,
  wantAssertionsSigned: true,
  wantAuthnResponseSigned: false,
  passReqToCallback: true,
}
const samlStrategy = new SamlStrategy(
  passportSamlConfig,
  // ✅ VerifyWithRequest: (req, profile, done)
  (req: express.Request, profile: Profile | null, done: VerifiedCallback) => {
    // you can inspect req here if you want
    return done(null, profile || {});
  },

  // ✅ Logout verify also WithRequest in this overload
  (req: express.Request, profile: Profile | null, done: VerifiedCallback) => {
    return done(null, {});
  }
);

passport.use("saml", samlStrategy);

app.get("/metadata", (_req, res) => {
  res.type("application/xml");
  res.send(samlStrategy.generateServiceProviderMetadata(decryptionCert, signingCert));
});

app.get("/login", passport.authenticate("saml", { failureRedirect: "/login/fail" }));

app.post(
  "/login/callback",
  passport.authenticate("saml", { failureRedirect: "/login/fail" }),
  (_req, res) => res.redirect("/me")
);

app.get("/login/fail", (_req, res) => res.status(401).send("SAML login failed"));

function requireAuth(req: any, res: any, next: any) {
  if (req.isAuthenticated?.()) return next();
  return res.status(401).send("Not authenticated. Go to /login");
}

app.get("/me", requireAuth, (req: any, res) => res.json({ user: req.user }));

app.post("/logout", (req: any, res) => {
  req.logout?.((err: any) => {
    if (err) return res.status(500).send(String(err));
    res.redirect("/");
  });
});


app.get("/", (_req, res) => {
  res.send(`<a href="/login">Login with SAML</a> | <a href="/me">/me</a>`);
});

app.listen(3000, () => console.log("SP listening on http://localhost:3000"));
