# Alt Alliance
## Requirements and Dependancies
* MySQL or compatible database
* Golang 1.7 (developed with 1.15, has been used with 1.1, but may require some fiddling, mainly from use of `context`. may require editing imports for golang.org/x/net/context)
* Go imports
  * goesi
  * goesi/optional
  * neucore-api-go
  * gorm
  * gorm/dialects/mysql
  * slack
  * oauth2

## ENV Vars and Command Line Params
alt-alliance requires the following environment variables set in order to function:
* `-u` or `DB_USER` - The username used to access the database.
* `-p` or `DB_PASS` - The password for the user.
* `-h` or `DB_HOST` - The hostname of the database to connect to (can be a unix socket, ip address, or domain.)
* `-d` or `DB_NAME` - The name of the database to use.

Command line params will overwrite ENV Vars.

## Config
alt-alliance will auto-create the required tables if they don't exist. If you prefer to create the config table yourself, use the following:
``` SQL
CREATE TABLE `configs` (
  `neucore_app_id`                     int unsigned DEFAULT NULL,
  `threads`                            int DEFAULT '20',
  `corp_tax_character_id`              int DEFAULT NULL,
  `corp_tax_corp_id`                   int DEFAULT NULL,
  `corp_base_tax_rate`                 double DEFAULT NULL,
  `corp_base_fee`                      double DEFAULT NULL,
  `request_timeout_in_seconds`         bigint DEFAULT '120',
  `corp_journal_update_interval_hours` int unsigned DEFAULT '24',
  `neucore_http_scheme`                varchar(255) DEFAULT 'http',
  `neucore_domain`                     varchar(255) DEFAULT NULL,
  `neucore_app_secret`                 varchar(255) DEFAULT NULL,
  `neucore_user_agent`                 varchar(255) DEFAULT NULL,
  `neucore_api_base`                   varchar(255) DEFAULT NULL,
  `esi_user_agent`                     varchar(255) DEFAULT NULL,
  `slack_webhook_url`                  varchar(255) DEFAULT NULL,
  `evemail_subject`                    varchar(255) DEFAULT NULL,
  `evemail_body`                       text
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
```

Example configuration:
``` SQL
INSERT INTO `configs` VALUES (
  1,
  20
  NULL, -- characterID who will send invoice evemails
  NULL, -- corporationID who will receive payments
  0.1,
  100000000,
  120,
  24,
  'http',
  'localhost:8080',
  'neucore-app-secret',
  'neucore-user-agent',
  NULL,
  'esi-user-agent',
  'https://hooks.slack.com/services/its/a/webhook',
  'Alliance Invoice for %s',                          -- %s here is the YYYY-MM-DD formatted date.
  "Pay us %s ISK or you'll never see your fedo again" -- %s here is the amount of isk owed.
);
```

## Check and Ignore Lists
Manually add an alliance to check:

`INSERT INTO checked_alliances (alliance_id) VALUES({alliance_id});`

Manually add an individual corp to check:

`INSERT INTO checked_corps (corp_id) VALUES({corp_id});`

Do not check a corporation, even if it's in a checked alliance or contained within the corp check list:

`INSERT INTO ignored_corps (corp_id) VALUES({corp_id});`

Do not check a corporation, even if it's in a checked alliance or contained within the corp check list:

`INSERT INTO ignored_characters (character_id) VALUES({character_id});`

## Building
### Build via Docker
alt-alliance can be built using the following docker command from the top level of the repository:
```
docker run -v $PWD:/build golang:1.16-alpine3.13 /bin/sh /build && go build ./...
```
or a stripped binary with
```
docker run -v $PWD:/build golang:1.16-alpine3.13 /bin/sh /build && go build -gcflags -trimpath=/build -ldflags "-s -w" ./...
```

### Building Manually
**NOTE:** exports will vary based on your installation/environment
``` bash
export GOPATH=$HOME/go
export GOBIN=$GOPATH/bin
export GOROOT=/usr/lib/go-1.10
export PATH="$PATH:${GOPATH}/bin:${GOROOT}/bin"

cd path/to/alt-alliance

go get ./...

go build
```
You may want to modify how go builds alt-alliance. For example to remove DWARF debugging info `-w`, GO symbols `-s`, and build machine paths `-trimpath`, you would want to run `go build -gcflags -trimpath=$PWD -ldflags "-s -w"`

## TODO
* Track corp taxes, fees, and payments
* Cache endpoint calls

## EVEMail Markup
### Special Characters and HTML Tags
Eve supports several standard html tags and special characters:
* `<br>` (force a new line)
* `<b>bold text</b>`
* `<i>italic text</i>`
* `<u>underlined text</u>`
* `<font size="12" color="#b3ffffff">text size and colour</font>`
* `<a href="http://www.example.com">hyperlinks</a>`
* `&lt;` <
* `&gt;` >

#### Colours
Using the `font` tag, you can specify the colour of your text in the hex format `#AARRGGBB` This differs from standard HTML with the addition of `AA` for an alpha (transperancy) value.
* Default text colour: `#b3ffffff`
* Type link colour: `#ffd98d00`

### Showinfo Links
You can also link to item types with a custom href of the following format:
``` html
<a href="showinfo:TypeID">Type Name</a>
```
for example: `<a href="showinfo:34">Tritanium</a>`

Some types also support linking a specific instance of that type in the format:
``` html
<a href="showinfo:TypeID//InstanceID">Specific Type Name</a>
```
for example: `<a href="showinfo:2//109299958">C C P</a>`

|   Type Name   | Type ID |
|--------------:|--------:|
| Character     |    1377 |
| Corporation   |       2 |
| Alliance      |   16159 |
| Region        |       3 |
| Constellation |       4 |
| Solar System  |       5 |
| Moon          |      14 |
| Asteroid Belt |      15 |
| Faction       |      30 |
| Raitaru       |   35825 |
| Azbel         |   35826 |
| Sotiyo        |   35827 |
| Astrahus      |   35832 |
| Fortizar      |   35833 |
| Keepstar      |   35834 |
| Athanor       |   35835 |
| Tatara        |   35836 |

#### Additional Examples
``` html
<a href="showinfo:2//109299958">C C P</a>
<a href="showinfo:16159//434243723">C C P Alliance</a>
<a href="showinfo:1529//60003466">Jita IV - Moon 4 - Caldari Business Tribunal Bureau Offices</a>
<a href="showinfo:52678//60003760">Jita IV - Moon 4 - Caldari Navy Assembly Plant</a>
<a href="showinfo:35834//1028858195912">Perimeter - Tranquility Trading Tower</a>
```

## Errata
* Upon the first run where a corp's most recent transaction was a payment made to the holdings corp, the first entry in the `corp_tax_payments` table will have a negative balance field.
