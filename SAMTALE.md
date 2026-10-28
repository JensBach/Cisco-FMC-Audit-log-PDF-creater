# Samtale: Fra idé til færdig FMC-rapport

Projektet er bygget i én samtale med GitHub Copilot CLI (Claude Opus 5.5). Mine beskeder er gengivet med rettede stavefejl, og svarene er forkortet. Kundenavne, IP'er og brugernavne er fjernet.

---

### 👤 Mig
> Jeg vil gerne have en C#-app, som henter audit-loggen fra en Cisco FMC via API.
>
> Jeg tror, endpointet er
> `/api/fmc_platform/v1/domain/{UUID}/audit/auditrecords?offset=0&limit=1000&starttime=1599007779&subsystem=Policies&expanded=true`
>
> Dataen skal vises pænt i en PDF, gerne med lidt grafik.
>
> Jeg har oprettet en `.password`-fil i dette format:
> ```
> host:10.x.x.x
> username:<api-bruger>
> password:XXXXXXXXXXXXXX
> ```
> Konvertér det til .NET user-secrets, så der ikke ligger en klartekstfil.
>
> Når det hele spiller og ser flot ud, så lav en PDF, som er anonymiseret, og gem den, så jeg kan vise den frem.
>
> Husk at FMC'en er en drift-FMC, så der må ikke laves ændringer på boksen.

### 🤖 Copilot
- Oprettede et .NET-konsolprojekt. Kun .NET 10 var installeret, så projektet blev målrettet `net10.0`.
- Importerede `.password` i user-secrets og overskrev og slettede filen.
- Byggede en FMC-klient, der kun laver GET-kald (plus login-token), med retry ved rate limit.
- Opdagede, at FMC'en højst returnerer ca. 100 records pr. kald uanset `limit`, og byggede derfor paging bagud i tid med `endtime`.
- Opdagede, at filteret `subsystem=Policies` gav 0 resultater, så rapporten dækker alle subsystemer.

### 👤 Mig
> PDF'en må gerne laves med QuestPDF.

### 🤖 Copilot
Det var allerede valgt. PDF'en bygges med QuestPDF, og diagrammerne er SVG (søjler, donut, stablede dage og aktivitet pr. time).

### 👤 Mig
> Download af data tager lang tid. Gem dataen som JSON, og brug den til test, indtil vi er i mål med, hvordan PDF'en skal se ud.

### 🤖 Copilot
- Tilføjede `auditlog-cache.json` og `--from-json`. Ca. 110.000 records for to uger blev hentet én gang.
- 98 % af data var API-GET-støj, så jeg lavede en klassificering i kategorier og omstrukturerede rapporten i afsnit: personers ændringer, deployments, automatiske ændringer, logins, drift og et API-bilag.

### 👤 Mig
> Jeg tror, vi skal undlade "internaladmin" og "ANUBIS:system-user".

### 🤖 Copilot
De udelades nu som standard (`--include-all` henter dem med). Der var herefter ca. 1.100 relevante hændelser på 10 sider. Anonymiseringen blev forbedret og leak-testet, og den første anonymiserede PDF blev genereret.

### 👤 Mig
> Lav også den rigtige, men put den i min Downloads-mappe. Det vil også være fedt med et policy-udtræk, så man kan se mere info om, hvad der er rettet. Jeg ved godt, at vi kun har de nyeste data, når rapporten kører, men se, hvad vi kan få.

### 🤖 Copilot
- Undersøgte API'et med GET-kald og fandt `metadata.timestamp` og `lastUser` på regler, objekter og policies samt deployment-jobhistorik.
- Byggede et policy-udtræk på 4 nye sider:
  - Policy-oversigt med KPI'er og diagrammer.
  - Ændrede access-regler, grupperet pr. gem og koblet til nærmeste "Save Policy"-hændelse i audit-loggen, så man kan se hvem.
  - Ændrede objekter.
  - Deployment-historik med enheder, versioner og noter.
- Rapporten forklarer, at FMC'en kun gemmer seneste ændring.
- Den rigtige PDF blev lagt i `~/Downloads`, og den anonymiserede blev lagt både i projektmappen og i Downloads.

### 👤 Mig
> Hvorfor er der en net8.0? Er alt ikke net10.0?

### 🤖 Copilot
Det var gammelt build-output fra før projektet blev skiftet til .NET 10. Det er slettet, og projektet er kun `net10.0`.

### 👤 Mig
> Hvad er "Default User"?

### 🤖 Copilot
Det er ikke en rigtig bruger. FMC'en bruger navnet for handlinger uden en indlogget bruger, dvs. planlagte backups og rapporter samt SAML-trinene før en SSO-bruger er identificeret.

### 👤 Mig
> Så vil jeg gerne omdøbe det til "Local System" og adskille SAML-logins før login som "SAML Prelogin".

### 🤖 Copilot
"Default User" deles nu i **SAML Prelogin** (SSO-trin) og **Local System** (resten, inkl. kilden "Default User IP"). PDF'erne blev genereret igen og verificeret.

### 👤 Mig
> Lav en .gitignore-fil med alt det, som vi ikke skal have med op på GitHub.

### 🤖 Copilot
`.gitignore` holder nu credentials, rå FMC-data (cache-filer), alle PDF'er samt build-, IDE- og OS-filer ude. Jeg tjekkede det i et testrepo, hvor kun kildekode, csproj og README kom med. Mit API-brugernavn i demodataen blev også fjernet.

### 👤 Mig
> Lav en prompt, der vil kunne lave dette projekt, og lav en fil med denne samtale. Jeg skal bruge det til at vise, hvor nemt det er at lave. Du må godt rette mine stavefejl :P

### 🤖 Copilot
Det er denne fil og [`PROMPT.md`](PROMPT.md).

---

## Resultat
- **Ca. 10 korte beskeder** fra idé til færdig app.
- Koden er en .NET 10-konsolapp på ca. 2.250 linjer: FMC-klient, cache, klassificering, anonymisering, policy-udtræk og PDF-rapport.
- En 17-siders PDF med diagrammer og en anonymiseret version, der er klar til fremvisning.
- **Nul ændringer på produktions-FMC'en.** Der blev kun lavet GET-kald.
