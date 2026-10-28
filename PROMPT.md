# Prompt: Cisco FMC Audit Log → PDF-rapport

Kopiér prompten herunder ind i GitHub Copilot CLI (eller en anden AI-kodeassistent) i en tom mappe.

---

Lav en C#-konsolapp i **.NET 10**, der henter audit-loggen fra en **Cisco FMC** via REST API og laver en flot PDF-rapport med grafik.

## Vigtigt: Read-only
FMC'en er en **produktions-FMC**. Appen må **kun lave GET-kald** (bortset fra login-tokenet). Der må under ingen omstændigheder laves ændringer på boksen.

## Credentials
- Jeg har en `.password`-fil i formatet:
  ```
  host:<ip>
  username:<api-bruger>
  password:<kodeord>
  ```
- Lav en `--import-secrets`-kommando, der flytter værdierne ind i **.NET user-secrets** (`Fmc:Host`, `Fmc:Username`, `Fmc:Password`) og derefter overskriver og sletter filen, så der ikke ligger kodeord i klartekst.
- Understøt også miljøvariabler med prefix `FMCAUDIT_`.

## Hentning af data
- Login: `POST /api/fmc_platform/v1/auth/generatetoken` (Basic auth). Brug headerne `X-auth-access-token` og `DOMAIN_UUID`.
- Audit: `GET /api/fmc_platform/v1/domain/{UUID}/audit/auditrecords?offset=0&limit=1000&starttime=<epoch>&expanded=true`.
- FMC'en returnerer højst ca. 100 records pr. kald uanset `limit`. Blad derfor bagud i tid med `endtime`, og fjern dubletter på `auditId`.
- Feltnavne kan variere i store/små bogstaver (fx `subSystem`), så parse dem case-insensitivt.
- Håndter rate limit (HTTP 429, 120 kald/min) med retry og genlogin ved 401.
- Accepter self-signed certifikat som standard (`--strict-tls` for at validere).
- Download tager lang tid, så **gem rå data som JSON** (`auditlog-cache.json`) og lav `--from-json`, så PDF'en kan itereres uden FMC-kald.

## Policy-udtræk (også kun GET)
Hent nuværende tilstand og sammenhold med audit-loggen:
- Access policies og deres regler (`/api/fmc_config/v1/domain/{UUID}/policy/accesspolicies/{id}/accessrules?expanded=true`) med zoner, netværk, porte, action, kategori, kommentarer og `metadata.timestamp`.
- NAT-, prefilter-, intrusion- og platform settings-policies (navn, senest ændret, af hvem).
- Objekter (hosts, networks, groups, ranges, FQDN, porte, URL'er, zoner) ændret i perioden.
- Deployment-historik (`/deployment/jobhistories`) med enheder, version, status og note.
- Gem det i `policy-cache.json`. FMC'en har kun seneste ændringstidspunkt pr. regel, så grupper regler med samme tidsstempel som ét "gem" og kobl dem til nærmeste `Save Policy`-hændelse i audit-loggen (±5 min) for at vise, hvem der stod bag.

## PDF (QuestPDF)
Lav en pæn rapport med QuestPDF og diagrammer (SVG), fx:
- Forside med KPI'er, donut-diagram over kategorier, aktivitet pr. dag og pr. time samt top-brugere.
- Ændringer foretaget af personer, deployments og automatiske ændringer (grupperet).
- Logins og sikkerhedshændelser, drift og system samt navigation i FMC'en.
- API-bilag (kun hvis der er mange API-kald).
- Policy-udtræk: oversigt, ændrede regler, ændrede objekter og deployment-historik.
- Klassificér hændelser i kategorier (konfiguration, deploy, API-ændring, sikkerhed, login, system, navigation, API-læsning), fordi langt de fleste records er API-GET-støj.

## Filtrering og navngivning
- Udelad `internaladmin` og `@ANUBIS:system-user` som standard (`--include-all` for at få dem med).
- FMC'en logger både planlagte opgaver og SAML-trin før login som "Default User". Omdøb SSO/SAML-trin til **"SAML Prelogin"** og resten til **"Local System"**.

## Anonymisering
- `--anonymize` laver en version til fremvisning: brugere → `user-A`, enheder → `FW-01`, objekter → `Object-001`, policies → `Policy-01`, regler, zoner og kategorier får pseudonymer, IP'er → RFC 5737-adresser, og kundenavn fra e-maildomæner → "Kunde".
- Pseudonymerne skal være konsistente på tværs af audit-data og policy-udtræk.
- Verificér bagefter, at der ikke er lækager, ved at søge i PDF-teksten efter rigtige navne og IP'er.

## Leverancer
- Den rigtige PDF i `~/Downloads`, og den anonymiserede PDF i projektmappen og i `~/Downloads`.
- `README.md` med brug og `.gitignore`, der holder credentials, cache-filer og PDF'er ude af git.
