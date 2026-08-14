# UpdateIP — Claude-muisti

Tämä tiedosto on tarkoitettu Claude-istunnoille konteksniksi tästä projektista. Ei julkinen dokumentaatio — pidetään pois selaimen/käyttäjien näkyvistä jos mahdollista, mutta `.gitignore` sallii tämän yhden poikkeuksen (ks. alla).

## 1. Projektin tarkoitus ja tausta

UpdateIP on Flask-sovellus, joka seuraa julkista IP-osoitetta ja päivittää Cloudflare DNS-tietueet automaattisesti kun IP muuttuu. Tukee multi-WAN-ympäristöjä UniFi-controllerin (UDM/UDM-Pro/UDM-SE/UCG) auto-tunnistuksella, integroituu Nginx Proxy Manageriin proxy-hostien hallintaan, ja tarjoaa mDNS-nimen (`updateip.local`) paikallisverkon käyttöön.

Solo-projekti: **Juha** on ainoa tekijä/ylläpitäjä (copyright nykyisin "BluexDEV Softwares", uudelleenbrändätty "Juha Lempiäinen" -nimestä 2026-07-02 — jos vanha nimi ilmestyy uudelleen mihinkään tiedostoon, se on regressio, ei tarkoituksellinen). Ei tiimikoodikanta — ei tarvetta huomioida PR-review-prosesseja tai muiden kontribuuttorien konventioita.

**Lisenssi:** Source Available, ei muokkausoikeutta (LICENSE-tiedosto kieltää eksplisiittisesti derivaatat ja muokattujen versioiden jakelun). README:n MIT-badge on virheellinen/vanhentunut — oikea lisenssi on huomattavasti rajoittavampi kuin standardi OSS.

**Repo:** todellinen remote on `git@github.com:JuhaFIN1/UpdateIP_Cloudflare.git` (SSH). Huom: koodin sisällä on kaksi eri vanhentunutta viittausta samaan repoon — `config.py`:n header-kommentti sanoo `JuhaFIN1/Updateip` ja README:n clone-esimerkki käyttää `YOUR_USERNAME/Updateip` -placeholderia. Kumpikaan ei täsmää — tarkista aina `git remote -v`.

## 2. Tuotantostatus — LIVE, ei demo

Tämä pyörii **oikeasti tuotannossa** Juhan omalla palvelimella:
- Isäntä: `192.168.1.215`, hostname `update-ip`, Debian GNU/Linux 13 (trixie), käyttäjä `root`.
- Working directory `/root/Updateip` ON suoraan `updateip.service`:n (systemd, gunicorn, `wsgi:app`) ajama koodi — ei erillistä build/deploy-vaihetta. Palvelu on `active` ja `enabled`.
- Integroi Juhan oikeaa infraa: UniFi-yhdyskäytävä, Cloudflare-tili, NPM-instanssi. Muutokset `unifi_api.py`/`cloudflare_api.py`/`npm_api.py`-tiedostoihin vaikuttavat oikeaan verkkoon, eivät testidataan.

**Käsittele muutoksia sen mukaisella vakavuudella:**
- Gunicorn/Python ei hot-reload:aa. Tiedostomuutokset (mukaan lukien `git pull`) eivät vaikuta ajossa olevaan prosessiin ennen `systemctl restart updateip` tai reboottia.
- `systemctl restart` lataa uuden *koodin*, mutta ei pakota uutta *dataa* — esim. `cf_records`-taulu päivittyy vasta kun synkka oikeasti ajetaan (ajastettu intervalli, "Sync"-nappi, tai dashboardin "Check & Update"). Restart yksin ei korjaa jämähtäneitä rivejä takautuvasti.
- Ennen tuotantoon vaikuttavia komentoja (restart, git-operaatiot livepalvelimella), **ehdota suunnitelma ja odota vahvistus** — älä aja suoraan ilman tarkistuspistettä (ks. kohta 5).

## 3. Käynnissä oleva työ / avoimet TODOt

Ei tunnettuja avoimia TODO-kohtia tai keskeneräisiä bugeja tämän katsauksen perusteella (viimeisin git-historia tarkistettu 2026-08-14, viimeisin committi `e6cac98` 2026-07-02). Jos uusia keskeneräisiä tehtäviä syntyy, päivitä tämä kohta — älä luota pelkkään git logiin niiden löytämiseksi, koska "miksi kesken" ei näy commiteista.

## 4. Tehdyt tekniset päätökset ja perustelut

**Cloudflare-tietueiden upsert käyttää `ON CONFLICT(id) DO UPDATE`, ei `INSERT OR REPLACE`** (`app.py`, useita kohtia mm. rivit ~401, ~412, ~511, ~1150-1158). Syy: `INSERT OR REPLACE` poistaisi ja lisäisi rivin uudelleen, jolloin paikalliset sarakkeet `auto_update` ja `wan_id` katoaisivat joka synkassa. Sivuvaikutus: pelkkä upsert ei koskaan poista rivejä jotka poistettiin Cloudflaressa suoraan (app:n ulkopuolella) — tämä oli oikea bugi ("haamutietueet" Records-sivulla). Korjattu committissa `df516bb` (2026-07-02) lisäämällä eksplisiittinen per-zone siivous: `DELETE FROM cf_records WHERE zone_id = ? AND id NOT IN (<juuri haetut Cloudflare-idt>)` (`app.py` ~rivi 422). **Älä yksinkertaista tätä takaisin pelkäksi upsertiksi** — se toisi bugin takaisin.

**WAN-kohtaiset DNS-tietueet eivät koskaan käytä auto-tunnistetun julkisen IP:n fallbackia.** `updater.py` (~rivit 113-130): jos tietueella on `wan_id` eikä kyseisen WAN:in IP ole juuri nyt saatavilla, päivitys **ohitetaan eksplisiittisesti** (kirjataan `update_log`-tauluun tilalla `skipped`) sen sijaan että pudottaisiin `auto_ip`:hen. Tarkoituksellinen valinta — fallback riskeeraisi väärän WAN:in IP:n kirjoittamisen tiettyyn WAN:iin sidottuun tietueeseen, mikä on pahempi kuin yhden kierroksen jättäminen päivittämättä.

## 5. Työskentelytapa-palaute (Juhan aiemmin antama)

- **Ehdota ennen ajoa.** Juha haluaa nähdä seuraavat askeleet (commit/push/restart) ennen kuin niitä oikeasti ajetaan — ei suoraa tuotantoon vientiä ilman tarkistuspistettä.
- **"Push githubiin" = molemmat haarat.** Kun hän sanoo tämän, odotus on että sekä `dev` että `main` päivittyvät (dev pushataan, sitten mergetään forward main:iin ja pushataan sekin) — ei pelkkä dev. Vahvistettu useasti. `main` liikkuu vain fast-forwardina `dev`:stä tässä repossa — jos joskus ei olisi fast-forwardattavissa, pysähdy ja kysy äläkä pakota mitään.
- **Saattaa haluta testata itse UI:sta ensin.** Kerran keskeytti skriptin ajon ("SORI ODOTA") koska halusi klikata dashboardin "Sync"-nappia itse ennen kuin backend-toiminto ajettaisiin suoraan. Jos UI-kontrolli tekee saman kuin komento jota olet aikeissa ajaa, harkitse kysyväsi haluaako hän tehdä sen itse.
- **Muista versio-/lisenssibumpit ilman erillistä pyyntöä.** Juha on johdonmukaisesti se joka huomauttaa `APP_VERSION`:n (`config.py`) ja copyright-headereiden päivitystarpeesta merkittävien muutosten yhteydessä. Ehdota versionostoa proaktiivisesti kun viet käyttäjänäkyvän korjauksen/ominaisuuden maaliin.
- **Repo-hygienia:** AI-avustajaan liittyvät tiedostot (`.github/`, `.claude/`, `CLAUDE.md`, `*memory*.md`) pidetään pois julkisesta GitHub-repositoriosta tarkoituksella — ne on listattu `.gitignore`:ssa. **Poikkeus:** tämä `CLAUDE_MEMORY.md` on eksplisiittisesti tarkoitettu committoitavaksi repoon (kts. kohta 7) — varmista ettei se osu `*memory*`-gitignore-sääntöön tiedostonimellä; jos se estää committoinnin, käytä `git add -f`.

## 6. SMB/Windows-jako vs. Linux-isäntä — tiedosto-oikeusongelma (löydetty ja vahvistettu 2026-08-14)

**Ongelma:** Repo on käytettävissä myös Windows-koneelta verkkojaon kautta (`\\192.168.1.215\UpdateIP\`, joka osoittaa suoraan tähän `/root/Updateip`-hakemistoon SMB:n yli). Windowsin SMB-klientti ei näe/säilytä Unixin suoritusoikeusbittiä (`+x`) oikein. Tämä saa gitin näyttämään `setup.sh`:n "muokattuna" Windows-puolelta katsottuna:

```
old mode 100755
new mode 100644
```
0 lisättyä/poistettua riviä, plus varoitus `LF will be replaced by CRLF`. **Vahvistettu vertailu 2026-08-14:** Windows-puolen `git status` näytti `setup.sh`:n muokattuna; SSH:lla suoraan `/root/Updateip`:iin ajettu `git status` oli **täysin puhdas** ("nothing to commit, working tree clean"). Tämä vahvistaa, ettei mikään ole oikeasti muuttunut — kyse on pelkästä SMB:n tavasta raportoida tiedosto-oikeuksia Windowsille.

**Riski:** Jos tämä committoidaan Windows-puolelta, `setup.sh` menettäisi suoritusoikeutensa pysyvästi Linux-puolella (ja mahdollisesti rivinvaihdot muuttuisivat CRLF:ksi), mikä rikkoisi skriptin ajettavuuden livepalvelimella.

**Sääntö tulevaisuudelle:** Älä koskaan tee `git add/commit/push`-komentoja tämän projektin Windows-jaon (`\\192.168.1.215\UpdateIP\` tai mikä tahansa mapattu asema joka osoittaa samaan) kautta. Kaikki git-kirjoitusoperaatiot tehdään SSH:lla suoraan isäntäkoneelle (`192.168.1.215`, käyttäjä `root`) — komentorivin `ssh`/`scp` jos toimii, tai Python + `paramiko` jos ei (Windowsin oletus-SSH-asiakas ei tue salasanapromptia non-interaktiivisessa ympäristössä; `paramiko` toimii ilman `sshpass`-riippuvuutta). Lukuoperaatiot (koodin tarkastelu, grep, tiedostojen lukeminen) Windows-jaon kautta ovat turvallisia — ongelma koskee vain kirjoitusta/committia.

**SSH-tunnistautuminen:** salasana kysytään käyttäjältä joka kerta erikseen — sitä **ei** tallenneta mihinkään tiedostoon, muistiin eikä tähän dokumenttiin. `~/.ssh/config`:ssa (Windows-puolella) on jo host-merkintä `192.168.1.215`:lle, mutta pelkkä avainautentikointi ei toiminut testissä (`Permission denied (publickey,password)`) — salasana vaadittiin.

## 7. Ulkoiset viitteet

- Git-repo: `git@github.com:JuhaFIN1/UpdateIP_Cloudflare.git` (SSH remote, toimii).
- Tuotantopalvelin: `192.168.1.215` (hostname `update-ip`), Debian 13, systemd-palvelu `updateip.service`, sama kone jolla `/root/Updateip` sijaitsee.
- Windows-puolen SMB-jako samaan koodiin: `\\192.168.1.215\UpdateIP\` — ks. kohta 6 ennen kuin kirjoitat mitään sitä kautta.
- Ei mainittuja issue-trackereita, Slack-kanavia tai muita ulkoisia työkaluja.
