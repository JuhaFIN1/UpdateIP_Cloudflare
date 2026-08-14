# UpdateIP — Claude-muisti

Tämä tiedosto on tarkoitettu Claude-istunnoille konteksniksi tästä projektista. Ei julkinen dokumentaatio — pidetään pois selaimen/käyttäjien näkyvistä jos mahdollista, mutta `.gitignore` sallii tämän yhden poikkeuksen (ks. alla).

## 1. Projektin tarkoitus ja tausta

UpdateIP on Flask-sovellus, joka seuraa julkista IP-osoitetta ja päivittää Cloudflare DNS-tietueet automaattisesti kun IP muuttuu. Tukee multi-WAN-ympäristöjä UniFi-controllerin (UDM/UDM-Pro/UDM-SE/UCG) auto-tunnistuksella, integroituu Nginx Proxy Manageriin proxy-hostien hallintaan, ja tarjoaa mDNS-nimen (`updateip.local`) paikallisverkon käyttöön.

Solo-projekti: **Juha** on ainoa tekijä/ylläpitäjä (copyright nykyisin "BluexDEV Softwares", uudelleenbrändätty "Juha Lempiäinen" -nimestä 2026-07-02 — jos vanha nimi ilmestyy uudelleen mihinkään tiedostoon, se on regressio, ei tarkoituksellinen). Ei tiimikoodikanta — ei tarvetta huomioida PR-review-prosesseja tai muiden kontribuuttorien konventioita.

**Lisenssi:** Source Available, ei muokkausoikeutta (LICENSE-tiedosto kieltää eksplisiittisesti derivaatat ja muokattujen versioiden jakelun). README:n MIT-badge on virheellinen/vanhentunut — oikea lisenssi on huomattavasti rajoittavampi kuin standardi OSS.

**Repo:** todellinen remote on `git@github.com:JuhaFIN1/UpdateIP_Cloudflare.git` (SSH). Huom: koodin sisällä on kaksi eri vanhentunutta viittausta samaan repoon — `config.py`:n header-kommentti sanoo `JuhaFIN1/Updateip` ja README:n clone-esimerkki käyttää `YOUR_USERNAME/Updateip` -placeholderia. Kumpikaan ei täsmää — tarkista aina `git remote -v`.

Juha ylläpitää useampaa samantyyppistä self-hosted-sovellusta ("BluexDEV"-ekosysteemi, mm. AdsOS, UpdateIP) ja ajaa niille yhteisiä retrofit-tehtäviä (ks. kohta 8) — jos tuntematon konsepti tulee vastaan, se saattaa olla jo ratkaistu jossain sisarprojektissa.

## 2. Tuotantostatus — LIVE, ei demo

Tämä pyörii **oikeasti tuotannossa** Juhan omalla palvelimella:
- Isäntä: `192.168.1.215`, hostname `update-ip`, Debian GNU/Linux 13 (trixie), käyttäjä `root`.
- Working directory `/root/Updateip` ON suoraan `updateip.service`:n (systemd, gunicorn, `wsgi:app`) ajama koodi — ei erillistä build/deploy-vaihetta. Palvelu on `active` ja `enabled`.
- Integroi Juhan oikeaa infraa: UniFi-yhdyskäytävä, Cloudflare-tili, NPM-instanssi, ja nyt myös auth.selaa.fi (ks. kohta 8). Muutokset `unifi_api.py`/`cloudflare_api.py`/`npm_api.py`-tiedostoihin vaikuttavat oikeaan verkkoon, eivät testidataan.

**Käsittele muutoksia sen mukaisella vakavuudella:**
- Gunicorn/Python ei hot-reload:aa. Tiedostomuutokset (mukaan lukien `git pull`) eivät vaikuta ajossa olevaan prosessiin ennen `systemctl restart updateip` tai reboottia.
- `systemctl restart` lataa uuden *koodin*, mutta ei pakota uutta *dataa* — esim. `cf_records`-taulu päivittyy vasta kun synkka oikeasti ajetaan (ajastettu intervalli, "Sync"-nappi, tai dashboardin "Check & Update"). Restart yksin ei korjaa jämähtäneitä rivejä takautuvasti.
- Ennen tuotantoon vaikuttavia komentoja (restart, git-operaatiot livepalvelimella), **ehdota suunnitelma ja odota vahvistus** — älä aja suoraan ilman tarkistuspistettä (ks. kohta 5).

## 3. Käynnissä oleva työ / avoimet TODOt

- **auth.selaa.fi SSO:n selainpolku ei ole vielä käyttäjän itse testaama.** Kaikki yksittäiset endpointit on curl-verifioitu ja koko koodi on livenä (ks. kohta 8), mutta täysi "kirjaudu sisään BluexDEV:llä" -klikkauspolku selaimessa (auth.selaa.fi:n oma login-lomake → paluu → sessio) vaatii Juhan itse tekemän testin — sitä ei voi todentaa curlilla. Kysy onko tämä testattu ennen kuin oletat SSO:n toimivan päästä päähän.
- Muuten ei tunnettuja avoimia TODO-kohtia tai keskeneräisiä bugeja tämän katsauksen perusteella (viimeisin git-historia tarkistettu 2026-08-14, viimeisin committi `012a63b`). Jos uusia keskeneräisiä tehtäviä syntyy, päivitä tämä kohta — älä luota pelkkään git logiin niiden löytämiseksi, koska "miksi kesken" ei näy commiteista.

## 4. Tehdyt tekniset päätökset ja perustelut

**Cloudflare-tietueiden upsert käyttää `ON CONFLICT(id) DO UPDATE`, ei `INSERT OR REPLACE`** (`app.py`, useita kohtia mm. rivit ~401, ~412, ~511, ~1150-1158). Syy: `INSERT OR REPLACE` poistaisi ja lisäisi rivin uudelleen, jolloin paikalliset sarakkeet `auto_update` ja `wan_id` katoaisivat joka synkassa. Sivuvaikutus: pelkkä upsert ei koskaan poista rivejä jotka poistettiin Cloudflaressa suoraan (app:n ulkopuolella) — tämä oli oikea bugi ("haamutietueet" Records-sivulla). Korjattu committissa `df516bb` (2026-07-02) lisäämällä eksplisiittinen per-zone siivous: `DELETE FROM cf_records WHERE zone_id = ? AND id NOT IN (<juuri haetut Cloudflare-idt>)` (`app.py` ~rivi 422). **Älä yksinkertaista tätä takaisin pelkäksi upsertiksi** — se toisi bugin takaisin.

**WAN-kohtaiset DNS-tietueet eivät koskaan käytä auto-tunnistetun julkisen IP:n fallbackia.** `updater.py` (~rivit 113-130): jos tietueella on `wan_id` eikä kyseisen WAN:in IP ole juuri nyt saatavilla, päivitys **ohitetaan eksplisiittisesti** (kirjataan `update_log`-tauluun tilalla `skipped`) sen sijaan että pudottaisiin `auto_ip`:hen. Tarkoituksellinen valinta — fallback riskeeraisi väärän WAN:in IP:n kirjoittamisen tiettyyn WAN:iin sidottuun tietueeseen, mikä on pahempi kuin yhden kierroksen jättäminen päivittämättä.

**auth.selaa.fi SSO täydentää, ei korvaa, paikallista admin/admin-loginia** ja hyväksyy vain `role == 'admin'`-vastauksia. Ks. kohta 8 perusteluineen.

## 5. Työskentelytapa-palaute (Juhan aiemmin antama)

- **Ehdota ennen ajoa.** Juha haluaa nähdä seuraavat askeleet (commit/push/restart) ennen kuin niitä oikeasti ajetaan — ei suoraa tuotantoon vientiä ilman tarkistuspistettä. Vahvistettu uudelleen 2026-08-14 auth.selaa.fi-retrofitin yhteydessä: koodi kirjoitettiin ja curl-testattiin ensin, lupa commit/push/restart-toimiin pyydettiin ja saatiin erikseen ennen kuin mitään tuotantoa koskettavaa ajettiin.
- **"Push githubiin" = molemmat haarat.** Kun hän sanoo tämän, odotus on että sekä `dev` että `main` päivittyvät (dev pushataan, sitten mergetään forward main:iin ja pushataan sekin) — ei pelkkä dev. Vahvistettu useasti. `main` liikkuu vain fast-forwardina `dev`:stä tässä repossa — jos joskus ei olisi fast-forwardattavissa, pysähdy ja kysy äläkä pakota mitään.
- **Saattaa haluta testata itse UI:sta ensin.** Kerran keskeytti skriptin ajon ("SORI ODOTA") koska halusi klikata dashboardin "Sync"-nappia itse ennen kuin backend-toiminto ajettaisiin suoraan. Jos UI-kontrolli tekee saman kuin komento jota olet aikeissa ajaa, harkitse kysyväsi haluaako hän tehdä sen itse.
- **Muista versio-/lisenssibumpit ilman erillistä pyyntöä.** Juha on johdonmukaisesti se joka huomauttaa `APP_VERSION`:n (`config.py`) ja copyright-headereiden päivitystarpeesta merkittävien muutosten yhteydessä. Ehdota versionostoa proaktiivisesti kun viet käyttäjänäkyvän korjauksen/ominaisuuden maaliin. (Sovellettu 2026-08-14: `0.86 beta` → `0.87 beta` osana auth.selaa.fi-retrofitia, ehdotettuna eikä pyydettynä.)
- **Salaisuuksia (salasanat, API-secretit) ei koskaan tallenneta muistiin/tiedostoihin oma-aloitteisesti — ei edes jos käyttäjä pyytää.** 2026-08-14: Juha pyysi eksplisiittisesti "tallenna nyt pysyvästi" SSH-root-salasanalle. Kieltäydyin ja selitin miksi (selkokielinen säilytys markdown-muistitiedostossa vs. hänen oma aiempi ohjeensa olla tallentamatta), ja ehdotin parempaa korjausta: avainpohjainen SSH-autentikointi. Juha hyväksyi tämän vaihtoehdon. **Opetus: jos käyttäjän tuore pyyntö on ristiriidassa hänen oman aiemman, harkitun ja toistuvasti kirjatun ohjeensa kanssa, on oikein kysyä/ehdottaa vaihtoehtoa sen sijaan että tottelisi suoraan** — tämä ei ollut virhe eikä käyttäjä pahoittanut mieltään, vaan hyväksyi paremman ratkaisun.
- **Repo-hygienia:** AI-avustajaan liittyvät tiedostot (`.github/`, `.claude/`, `CLAUDE.md`, `*memory*.md`) pidetään pois julkisesta GitHub-repositoriosta tarkoituksella — ne on listattu `.gitignore`:ssa. **Poikkeus:** tämä `CLAUDE_MEMORY.md` on eksplisiittisesti tarkoitettu committoitavaksi repoon (kts. kohta 7) — varmista ettei se osu `*memory*`-gitignore-sääntöön tiedostonimellä; jos se estää committoinnin, käytä `git add -f`.

## 6. SMB/Windows-jako vs. Linux-isäntä — tiedosto-oikeusongelma (löydetty 2026-08-14, vahvistettu MOLEMPIIN suuntiin)

**Ongelma:** Repo on käytettävissä myös Windows-koneelta verkkojaon kautta (`\\192.168.1.215\UpdateIP\`, joka osoittaa suoraan tähän `/root/Updateip`-hakemistoon SMB:n yli, ja Windows-puolella myös `D:\BluexDEV\UpdateIP-LXC` -nimisenä symlinkkinä samaan jakoon). Windowsin SMB-klientti ei välitä Unixin suoritusoikeusbittiä (`+x`) oikein kumpaankaan suuntaan git:lle.

**Suunta 1 (bitin katoaminen):** `setup.sh` näytti Windows-puolelta "muokattuna" 0 lisätyllä/poistetulla rivillä, `old mode 100755 / new mode 100644`. SSH:lla suoraan isäntäkoneelle ajettu `git status` oli samalla hetkellä täysin puhdas — pelkkä SMB-artefakti.

**Suunta 2 (bitin ilmestyminen — vahvistettu toisen kerran, auth.selaa.fi-retrofit-sessio):** kun `app.py`, `config.py`, `database.py` ja kolme templatea muokattiin Windows-jaon kautta, SMB asetti niihin **vahingossa +x-bitin** (`100644` → `100755`) vaikka mikään niistä ei ole skripti. Sama juurisyy kuin sisarprojekti AdsOS:ssa kohdattiin ja korjattiin (sen commit `5ae0927`). Tässä korjattiin `chmod 644` SSH:lla ja committoitiin erillisenä `chore: fix file modes...`-committina (`012a63b`) ennen pushia, jotta varsinainen ominaisuuscommit pysyi puhtaana.

**Riski:** Jos moodivirhe committoidaan huomaamatta, `setup.sh` menettäisi ajettavuutensa TAI tavalliset lähdekooditiedostot saisivat tarpeettoman +x-bitin — kumpikin on epäsiisti mutta jälkimmäinen ei riko toiminnallisuutta, edellinen rikkoisi deployn.

**Sääntö tulevaisuudelle:**
- Älä koskaan tee `git add/commit/push`-komentoja tämän projektin Windows-jaon (`\\192.168.1.215\UpdateIP\`, `D:\BluexDEV\UpdateIP-LXC`, tai mikä tahansa mapattu asema joka osoittaa samaan) kautta. Kaikki git-kirjoitusoperaatiot SSH:lla suoraan isäntäkoneelle.
- **Tarkista AINA `git diff --stat` SSH:n kautta ennen stagea** — jos näet mode-only-muutoksen (0 sisältöriviä, `old mode`/`new mode`) millä tahansa juuri muokatulla tiedostolla, `chmod` se takaisin oikeaksi ennen committia, tarvittaessa omana committinaan.
- Lukuoperaatiot (koodin tarkastelu, grep, tiedostojen lukeminen/kirjoittaminen levylle) Windows-jaon kautta ovat turvallisia — ongelma koskee vain git-kirjoitusta.

**SSH-tunnistautuminen — päivitetty 2026-08-14, ei enää salasanaa:** Windows-koneelle luotiin oma avainpari (`~/.ssh/id_updateip_ed25519`), julkinen avain lisätty `/root/.ssh/authorized_keys`-tiedostoon, ja `~/.ssh/config`:iin lisätty vastaava `IdentityFile`-rivi `Host 192.168.1.215` -kohtaan. `ssh 192.168.1.215` toimii nyt täysin salasanattomasti. Root-salasanaa käytettiin vain kertaluontoisesti avaimen asennukseen eikä sitä tallennettu mihinkään pysyvään paikkaan — jos avain joskus mitätöityy, kysy salasana käyttäjältä tuoreena, älä oleta mitään vanhaa arvoa oikeaksi.

## 7. Ulkoiset viitteet

- Git-repo: `git@github.com:JuhaFIN1/UpdateIP_Cloudflare.git` (SSH remote, toimii).
- Tuotantopalvelin: `192.168.1.215` (hostname `update-ip`), Debian 13, systemd-palvelu `updateip.service`, sama kone jolla `/root/Updateip` sijaitsee.
- Windows-puolen SMB-jako samaan koodiin: `\\192.168.1.215\UpdateIP\` / `D:\BluexDEV\UpdateIP-LXC` — ks. kohta 6 ennen kuin kirjoitat mitään sitä kautta.
- **auth.selaa.fi** (Juhan oma BluexDEV-alustapalvelin): `https://auth.selaa.fi`, lähdekoodi Windows-koneella `D:\BluexDEV\auth-selaa-fi` (paikallinen kopio, ei SMB-jako). UpdateIP rekisteröity siellä sovelluksena slugilla `updateip`. Ks. kohta 8.
- Sisarprojekti-referenssi samalle retrofit-standardille: `D:\BluexDEV\AdsOS-LXC` (symlink `\\192.168.1.227\AdsOS`), integraatiocommit `03c60c0` + filemode-fix `5ae0927`.
- Ei mainittuja issue-trackereita, Slack-kanavia tai muita ulkoisia työkaluja.

## 8. auth.selaa.fi (BluexDEV-alusta) -integraatio — toteutettu 2026-08-14

UpdateIP retrofitattiin Juhan "19-pisteen standardiin" auth.selaa.fi-alustaintegraatiolle. Rekisteröity sovelluksena slugilla `updateip`; `api_key`/`api_secret` ovat vain sovelluksen omassa SQLite `app_settings`-taulussa (Settings → "BluexDEV (auth.selaa.fi)" -kortti), eivät tässä tiedostossa eivätkä missään muussakaan muistissa.

**Committit:** `dafb3c9` (pääominaisuus) + `012a63b` (SMB-moodikorjaus), sekä `dev` että `main`.

**Toteutettu:**
- **1. SSO** — täydentää paikallista admin/admin-loginia (`/auth/sso/login`, `/auth/sso/callback`), hyväksyy vain `role == 'admin'`, paikallinen salasananvaihto estetty SSO-sessioilta (ei paikallista `users`-riviä päivitettäväksi). Callback rekisteröity auth.selaa.fi:n admin-paneelissa kiinteänä LAN-IP:nä `http://192.168.1.215/auth/sso/callback` (tarkoituksella ei muutettavaa mDNS-nimeä, jotta rekisteröinti ei riko jos hostname vaihdetaan Settingsissä myöhemmin).
- **6–14, 19** — heartbeat (5min), etäkomennot rajattuna whitelistinä (`check_update`, `force_sync` — molemmat kääntävät jo olemassa olevia manuaalisia UI-toimintoja, eivät tuo uutta kykyä), feature-flagit+config (mekanismi, ei vielä käytössä mihinkään), versiotarkistus (RINNAKKAINEN, ei korvaa GitHub-itsepäivitystä), tiedotteet/changelog/alustatiedotteet (dashboard-kortti, piilossa kun tyhjä), kriittisten lokien+Telegram-forwarding (koodi valmis, botti Juhan asennettavana).
- **15/17 (piece-sync)** — koodattu muttei ajastettu/kutsuttu mistään (dormant) — SDK:n `current_version` on null palvelinpuolella koko alustalle, ei UpdateIP:n korjattava. Aktivoidaan kun Juha vahvistaa.
- **18** — vahvistettu aito poikkeus: `.github/workflows/` ei ole olemassa tässä repossa.

**Live-verifioitu 2026-08-14** (curl oikeilla tunnuksilla + suora ajo sovelluksen omasta koodista SSH:lla): kaikki `/api/v1/agent/*`- ja info-endpointit 200/201, vastausmuodot täsmäävät koodiin tarkalleen. `GET /sso/init?app=updateip` → 302 oikeaan piilotettuun login-polkuun (todistaa rekisteröinnin aktiiviseksi). Ensimmäinen oikea heartbeat käynnissä olevasta prosessista onnistui (`AUTH_SELAA_FI_HEARTBEAT_LAST` päivittyi). Flags/config/version/notifications/changelog/platform-announcements ajettu suoraan tuotantokoodista SSH:n kautta — kaikki onnistuivat ja tallensivat odotetut (tyhjät, koska auth.selaa.fi-puolella ei ole vielä dataa tälle sovellukselle) arvot.

**Ei voitu vahvistaa:** SSO:n täysi selainpolku (ks. kohta 3) — vaatii Juhan oman klikkauksen.

Yksityiskohtaisempi referenssimateriaali (mistä lukea auth.selaa.fi:n API-sopimus, sisarprojektin AdsOS:n vastaava toteutus) on kirjattu Claude-session omaan pysyvään muistiin, ei tähän repoon — kysy jos tarvitset niitä uudelleen jonkin muun sisarprojektin retrofitissä.
