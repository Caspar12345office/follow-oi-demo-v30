# Follow O-I Web Complete - v9 + Circulaire Marketplace

## Starten
1. Pak de zip uit.
2. Dubbelklik op `start_windows.bat`.
3. Open http://127.0.0.1:5000

## Eerste login
caspar@office-interior.nl  
ChangeMe123!

## Toegevoegd in deze versie
- Alleen een nieuwe module **Circulaire marketplace** onder het menu **Meubilair**.
- Vanuit **Meubilair > Huidig meubilair** kan een asset beschikbaar worden gemaakt voor interne herplaatsing.
- Facility managers kunnen beschikbare assets bekijken en reserveren.
- Reserveringen worden vastgelegd op het asset.

## Belangrijk
De bestaande modules, styling en structuur zijn verder ongemoeid gelaten.

## v9 + Marketplace Office-Interior style
- Originele opzet en modules behouden.
- Circulaire marketplace toegevoegd onder Meubilair.
- Klanten kunnen zelf een nieuw product op de marketplace plaatsen.
- Vaste contactpersoon Caspar Mastenbroek blijft zichtbaar in het klantportaal en marketplace.
- Office-Interior kleurstelling hersteld in de template.

## v9 + Marketplace + Talen
- Office-Interior styling behouden.
- Vast aanspreekpunt terug op dashboard: Caspar Mastenbroek, Sales Director.
- Meubilair-menu is inklapbaar/uitklapbaar.
- Circulaire marketplace toegevoegd onder Meubilair.
- Klant kan zelf een product/item op de marketplace plaatsen.
- Tabje Talen toegevoegd met keuze Nederlands of English, zonder layoutwijziging.


## v9 marketplace languages - final fix
- Vast aanspreekpunt staat alleen op dashboard.
- Caspar Mastenbroek staat als Sales Director vermeld.
- Algemene contactregel toegevoegd bij vast aanspreekpunt.
- Tickets-menu inklapbaar gemaakt met Schade en Schade melden eronder.
- Lopende schades zichtbaar in het schadeoverzicht.
- Huidig meubilair toont conditie, uitleverdatum en laatste servicedatum.
- Office-Interior styling en layout verder ongewijzigd gelaten.


## v9 vervolgfix
- Los tabje Schade verwijderd; alleen Schade melden onder Tickets blijft zichtbaar.
- Schade melden toont ook lopende schades in hetzelfde overzicht.
- Offertes is inklapbaar met Offerteoverzicht en Offerte aanvragen als subtabs.
- Dashboard toont algemeen contact bij afwezigheid: info@office-interior.com en 085-0481444.


## Marketplace productfoto
- Bij Nieuw product plaatsen kan een productfoto worden geupload.
- De foto wordt opgeslagen in uploads/ en zichtbaar gemaakt in het marketplace-overzicht.
- Verder zijn layout en bestaande functies ongemoeid gelaten.

## v31 - Beveiliging, persistentie en vormgeving
- Wachtwoorden worden nu veilig gehasht (scrypt). Bestaande wachtwoorden migreren automatisch bij de eerstvolgende login.
- Secret key komt uit de omgevingsvariabele `SECRET_KEY`; lokaal wordt een sleutel bewaard in `.secret_key`.
- Database en uploads zijn instelbaar via `FOLLOW_OI_DB_PATH` en `FOLLOW_OI_UPLOAD_FOLDER` (op Render naar een persistente schijf, zie render.yaml).
- `init_db()` draait nu ook onder gunicorn, zodat de database ook bij een verse deploy wordt aangemaakt.
- Nieuw menu **Vormgeving** (alleen admin): pas kleuren, lettertype, logo en merknaam aan via de front-end. Wijzigingen blijven bewaard en gelden voor de hele tool.

### Lokaal draaien
1. `python -m pip install -r requirements.txt`
2. `python app.py`
3. Open http://127.0.0.1:5000 (login: caspar@office-interior.nl / ChangeMe123!)

### Render (productie)
Zet in het dashboard de environment variables `SECRET_KEY`, `FOLLOW_OI_DB_PATH=/var/data/follow_oi.db` en `FOLLOW_OI_UPLOAD_FOLDER=/var/data/uploads`, en koppel een persistente schijf op `/var/data` (staat al in render.yaml).
