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
  `threads`                            int DEFAULT NULL
  `corp_tax_character_id`              int DEFAULT NULL,
  `corp_tax_corp_id`                   int DEFAULT NULL,
  `corp_base_tax_rate`                 double DEFAULT NULL,
  `corp_base_fee`                      double DEFAULT NULL,
  `corp_journal_update_interval_hours` int unsigned DEFAULT NULL,
  `neucore_http_scheme`                varchar(255) DEFAULT NULL,
  `neucore_domain`                     varchar(255) DEFAULT NULL,
  `neucore_app_secret`                 varchar(255) DEFAULT NULL,
  `neucore_user_agent`                 varchar(255) DEFAULT NULL,
  `neucore_api_base`                   varchar(255) DEFAULT NULL,
  `esi_user_agent`                     varchar(255) DEFAULT NULL,
  `slack_webhook_url`                  varchar(255) DEFAULT NULL,
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
```

Example configuration:
``` SQL
INSERT INTO `configs` VALUES (
  1,
  20
  NULL,
  NULL,
  0.1,
  100000000,
  1,
  'http',
  'localhost:8080',
  'neucore-secret',
  'neucore-user-agent',
  'esi-user-agent',
  'https://hooks.slack.com/services/its/a/webhook',
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
