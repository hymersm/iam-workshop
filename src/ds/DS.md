Below is a **minimal, repeatable “directory-lab” baseline**: an LDAP directory server + a web-based admin UI, both in Docker. This is the quickest way to start experimenting with bind/search/modify/schema without bringing in heavier IAM stacks.

I’m using the very common **osixia/openldap** + **osixia/phpldapadmin** pairing (the phpLDAPadmin image is explicitly designed to point at an LDAP host via env vars). ([GitHub][1])

---

## 1) `docker-compose.yml`

Create a folder (e.g. `directory-lab/`) and add this file:

```yaml
services:
  openldap:
    image: osixia/openldap:latest
    container_name: directory-lab-openldap
    environment:
      LDAP_ORGANISATION: "Directory Lab"
      LDAP_DOMAIN: "example.org"
      LDAP_ADMIN_PASSWORD: "adminpassword"
      # Optional: enable verbose logs while learning
      LDAP_LOG_LEVEL: "256"
    ports:
      - "389:389"   # LDAP
      - "636:636"   # LDAPS
    volumes:
      - openldap_data:/var/lib/ldap
      - openldap_config:/etc/ldap/slapd.d
      # Drop LDIF files in ./ldif to auto-seed at first start
      - ./ldif:/container/service/slapd/assets/config/bootstrap/ldif/custom:ro
    restart: unless-stopped

  phpldapadmin:
    image: osixia/phpldapadmin:latest
    container_name: directory-lab-phpldapadmin
    environment:
      PHPLDAPADMIN_LDAP_HOSTS: "openldap"
      PHPLDAPADMIN_HTTPS: "false"  # keep simple for local lab
    ports:
      - "18081:80"
    depends_on:
      - openldap
    restart: unless-stopped

volumes:
  openldap_data:
  openldap_config:
```

This layout mirrors the upstream “openldap + phpldapadmin” compose example and the phpLDAPadmin env-var configuration approach. ([GitHub][1])

---

## 2) Start it

```bash
docker compose up -d
docker compose ps
```

You should now have:

* LDAP on **localhost:389**
* phpLDAPadmin on **[http://localhost:18081](http://localhost:18081)**

---

## 3) Login details (phpLDAPadmin)

In phpLDAPadmin:

* **Login DN**: `cn=admin,dc=example,dc=org`
* **Password**: `adminpassword`

Base DN is derived from `LDAP_DOMAIN=example.org` → `dc=example,dc=org`.

---

## 4) Seed some entries (optional but recommended)

Create a folder `ldif/` next to your compose file and add `ldif/01-bootstrap.ldif`:

```ldif
dn: ou=people,dc=example,dc=org
objectClass: organizationalUnit
ou: people

dn: ou=groups,dc=example,dc=org
objectClass: organizationalUnit
ou: groups

dn: uid=martin,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
cn: Martin Hymers
sn: Hymers
uid: martin
mail: martin@example.org
userPassword: password123
```

Then recreate once (seeding happens on first init):

```bash
docker compose down -v
docker compose up -d
```

---

## 5) Quick CLI verification (bind + search)

If you have `ldapsearch` locally:

```bash
ldapsearch -x \
  -H ldap://localhost:389 \
  -D "cn=admin,dc=example,dc=org" \
  -w adminpassword \
  -b "dc=example,dc=org" "(objectClass=*)"
```

Or run it inside the container (no local tooling needed):

```bash
docker exec -it directory-lab-openldap bash -lc \
'ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=org" -w adminpassword -b "dc=example,dc=org" "(objectClass=*)"'
```

---

## 6) Notes

* **Persistence**: you get durable storage via the named volumes (`openldap_data`, `openldap_config`). Blow them away with `docker compose down -v` when you want a clean slate.
* **Observability**: crank up `LDAP_LOG_LEVEL` to learn what ops look like server-side (you’ll see binds/searches/modifies in logs).
* **LDAPS**: it’s exposed on 636, but I’d keep most early experiments on plain LDAP for clarity, then add TLS once you’re comfortable with the protocol.

[1]: https://github.com/osixia/docker-openldap/blob/master/example/docker-compose.yml?utm_source=chatgpt.com "docker-openldap/example/docker-compose.yml at master"
