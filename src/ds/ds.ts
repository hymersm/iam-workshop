import express from "express";
import bodyParser from "body-parser";
import * as utils from "./utils";
import { Client } from "ldapts";
import type { Request, Response } from "express";

const LDAP_URL="ldap://localhost:389";
const LDAP_BIND_DN="cn=admin,dc=example,dc=org";
const LDAP_BIND_PASSWORD="adminpassword";

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());

// --- Endpoint: GET /directory/info ---
app.get("/directory/info", async (req: Request, res: Response) => {
  // Prefer env config (best for services); allow override via query for quick lab testing.
  const ldapUrl = String(req.query.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");

  // Optional bind: RootDSE is usually readable anonymously in many servers,
  // but some lock it down; support bind creds via env.
  const bindDn = String(req.query.bindDn ?? LDAP_BIND_DN ?? "");
  const bindPassword = String(req.query.bindPassword ?? LDAP_BIND_PASSWORD ?? "");

  try {
    const info = await utils.fetchDirectoryInfo(
      ldapUrl,
      bindDn || undefined,
      bindPassword || undefined
    );

    res.json(info);
  } catch (err: any) {
    res.status(502).json({
      error: "DIRECTORY_INTROSPECTION_FAILED",
      message: err?.message ?? String(err),
      ldapUrl,
    });
  }
});

app.get("/directory/capabilities", async (req: Request, res: Response) => {
  // Prefer env config (best for services); allow override via query for quick lab testing.
  const ldapUrl = String(req.query.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");

  // Optional bind: RootDSE is usually readable anonymously in many servers,
  // but some lock it down; support bind creds via env.
  const bindDn = String(req.query.bindDn ?? LDAP_BIND_DN ?? "");
  const bindPassword = String(req.query.bindPassword ?? LDAP_BIND_PASSWORD ?? "");

  try {
    const info = await utils.fetchDirectoryInfo(
      ldapUrl,
      bindDn || undefined,
      bindPassword || undefined
    );

    res.json({
      ...info,
      controls: utils.describeOids(info.supportedControls, "control"),
      extensions: utils.describeOids(info.supportedExtensions, "extension"),
      features: info.raw?.supportedFeatures
        ? utils.describeOids(info.raw.supportedFeatures as string[], "feature")
        : [],
    });
  } catch (err: any) {
    res.status(502).json({
      error: "DIRECTORY_CAPABILITIES_FAILED",
      message: err?.message ?? String(err),
    });
  }
});

const WHOAMI_OID = "1.3.6.1.4.1.4203.1.11.3";

app.get("/directory/whoami", async (req: Request, res: Response) => {
  const ldapUrl = String(req.query.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");
  const bindDn = String(req.query.bindDn ?? LDAP_BIND_DN ?? "");
  const bindPassword = String(req.query.bindPassword ?? LDAP_BIND_PASSWORD ?? "");

  const client = new Client({ url: ldapUrl, timeout: 10_000, connectTimeout: 10_000 });

  try {
    const info = await utils.fetchDirectoryInfo(
      ldapUrl,
      bindDn || undefined,
      bindPassword || undefined
    );
    const supportsWhoAmI = info.supportedExtensions.includes(WHOAMI_OID);

    if (!supportsWhoAmI) {
      return res.status(501).json({
        supported: false,
        oid: WHOAMI_OID,
        message: "Server does not advertise Who Am I? extended operation support.",
      });
    }

    if (!bindDn || !bindPassword) {
      return res.status(400).json({
        error: "BAD_REQUEST",
        message: "bindDn and bindPassword are required for whoami",
      });
    }

    await client.bind(bindDn, bindPassword);

    const { value } = await client.exop(WHOAMI_OID);

    return res.json({
      supported: true,
      oid: WHOAMI_OID,
      authzId: value ?? null,
    });
  } catch (err: any) {
    return res.status(502).json({
      error: "DIRECTORY_WHOAMI_FAILED",
      message: err?.message ?? String(err),
      ldapUrl,
    });
  } finally {
    try {
      await client.unbind();
    } catch {
      /* ignore */
    }
  }
});

/*
curl -s http://localhost:3001/directory/auth/test \
  -H "content-type: application/json" \
  -d '{
    "bindDn": "cn=admin,dc=example,dc=org",
    "bindPassword": "adminpassword"
  }' | jq .
*/
app.post("/directory/auth/test", async (req: Request, res: Response) => {
  const body = req.body as Partial<utils.AuthTestBody>;

  const ldapUrl = String(body.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");
  const bindDn = String(body.bindDn ?? "");
  const bindPassword = String(body.bindPassword ?? "");

  if (!bindDn || !bindPassword) {
    return res.status(400).json({
      error: "BAD_REQUEST",
      message: "bindDn and bindPassword are required",
    });
  }

  const client = new Client({ url: ldapUrl, timeout: 10_000, connectTimeout: 10_000 });

  try {
    // Bind test
    await client.bind(bindDn, bindPassword);

    // Check if WhoAmI is supported (Root DSE)
    const info = await utils.fetchDirectoryInfo(ldapUrl, bindDn, bindPassword);
    const supportedWhoAmI = info.supportedExtensions.includes(WHOAMI_OID);

    let authzId: string | null = null;
    if (supportedWhoAmI) {
      const { value } = await client.exop(WHOAMI_OID);
      authzId = value ?? null;
    }

    return res.json({
      ok: true,
      supportedWhoAmI,
      authzId,
    });
  } catch (err: any) {
    // Common LDAP bind failures are typically invalidCredentials, etc.
    return res.status(401).json({
      ok: false,
      error: "AUTH_TEST_FAILED",
      message: err?.message ?? String(err),
    });
  } finally {
    try {
      await client.unbind();
    } catch {
      /* ignore */
    }
  }
});

app.get("/directory/schema", async (req: Request, res: Response) => {
  const ldapUrl = String(req.query.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");
  const bindDn = String(req.query.bindDn ?? LDAP_BIND_DN ?? "");
  const bindPassword = String(req.query.bindPassword ?? LDAP_BIND_PASSWORD ?? "");

  const q = String(req.query.q ?? "").trim().toLowerCase();

  try {
    const schema = await utils.fetchSchemaSummary(
      ldapUrl,
      bindDn || undefined,
      bindPassword || undefined
    );

    // Optional filter by name
    if (q) {
      schema.objectClasses = schema.objectClasses.filter((o) => o.name.toLowerCase().includes(q));
      schema.attributeTypes = schema.attributeTypes.filter((a) => a.name.toLowerCase().includes(q));
    }

    res.json(schema);
  } catch (err: any) {
    res.status(502).json({
      error: "DIRECTORY_SCHEMA_FAILED",
      message: err?.message ?? String(err),
      ldapUrl,
    });
  }
});

type SearchBody = {
  ldapUrl?: string;
  bindDn?: string;
  bindPassword?: string;

  baseDn: string;
  scope?: "base" | "one" | "sub";
  filter: string;
  attributes?: string[];

  sizeLimit?: number;  // max entries
  timeLimitSeconds?: number; // server-side time limit
};

const DEFAULT_ATTRS = ["dn", "cn", "sn", "uid", "mail", "ou", "memberOf"];

function sanitizeAttributes(attrs?: string[]): string[] {
  const a = (attrs?.length ? attrs : DEFAULT_ATTRS).map(String);
  const blocked = new Set(["userpassword", "olcrootpw"]);
  return a.filter(x => x && !blocked.has(x.toLowerCase()));
}


/*
curl -s http://localhost:3001/directory/search \
  -H "content-type: application/json" \
  -d '{
    "baseDn": "dc=example,dc=org",
    "scope": "sub",
    "filter": "(objectClass=*)",
    "attributes": ["dn","objectClass","cn","sn","uid","mail"],
    "sizeLimit": 50
  }' | jq .
*/
app.post("/directory/search", async (req: Request, res: Response) => {
  const body = req.body as Partial<SearchBody>;

  const ldapUrl = String(body.ldapUrl ?? LDAP_URL ?? "ldap://localhost:389");
  const bindDn = String(body.bindDn ?? LDAP_BIND_DN ?? "");
  const bindPassword = String(body.bindPassword ?? LDAP_BIND_PASSWORD ?? "");

  const baseDn = String(body.baseDn ?? "");
  const scope = (body.scope ?? "sub") as "base" | "one" | "sub";
  const filter = String(body.filter ?? "").trim();

  if (!baseDn || !filter) {
    return res.status(400).json({
      error: "BAD_REQUEST",
      message: "baseDn and filter are required",
    });
  }

  // Guardrails
  const sizeLimit = Math.min(Math.max(Number(body.sizeLimit ?? 50), 1), 200);
  const timeLimitSeconds = Math.min(Math.max(Number(body.timeLimitSeconds ?? 5), 1), 15);
  const attributes = sanitizeAttributes(body.attributes);

  const client = new Client({ url: ldapUrl, timeout: 10_000, connectTimeout: 10_000 });

  const start = Date.now();
  try {
    await client.bind(bindDn, bindPassword);

    const result = await client.search(baseDn, {
      scope,
      filter,
      attributes,
      sizeLimit,
      timeLimit: timeLimitSeconds,
      // typesOnly: false,
    });

    res.json({
      ok: true,
      tookMs: Date.now() - start,
      count: result.searchEntries.length,
      entries: result.searchEntries,
    });
  } catch (err: any) {
    res.status(502).json({
      ok: false,
      error: "DIRECTORY_SEARCH_FAILED",
      message: err?.message ?? String(err),
      tookMs: Date.now() - start,
    });
  } finally {
    try { await client.unbind(); } catch {}
  }
});

app.listen(3001, () => console.log("DS discovery listening on http://localhost:3001"));
