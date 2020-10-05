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

## ENV Vars
alt-alliance requires the following environment variables set in order to function:
* `DB_USER` - The username used to access the database.
* `DB_PASS` - The password for the user.
* `DB_HOST` - The hostname of the database to connect to (can be a unix socket, ip address, or domain.)
* `DB_NAME` - The name of the database to use.

## Config
alt-alliance will auto-create the required tables if they don't exist. If you prefer to create the config table yourself, use the following:
``` SQL
CREATE TABLE `configs` (
  `neucore_http_scheme`   varchar(255) DEFAULT NULL,
  `neucore_domain`        varchar(255) DEFAULT NULL,
  `neucore_app_id`        int unsigned DEFAULT NULL,
  `neucore_app_secret`    varchar(255) DEFAULT NULL,
  `neucore_user_agent`    varchar(255) DEFAULT NULL,
  `neucore_api_base`      varchar(255) DEFAULT NULL,
  `esi_user_agent`        varchar(255) DEFAULT NULL,
  `slack_webhook_url`     varchar(255) DEFAULT NULL,
  `corp_base_fee`         double DEFAULT NULL,
  `corp_tax_character_id` int DEFAULT NULL,
  `corp_base_tax_rate`    double DEFAULT NULL,
  `threads`               int DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
```

Example configuration:
``` SQL
INSERT INTO `configs` VALUES (
	'http',
	'localhost:8080',
	1,
	'neucore-secret',
	'neucore-user-agent',
	NULL,
	'esi-user-agent',
	'https://hooks.slack.com/services/its/a/webhook',
	100000000,
	0,
	0.1,
	20
);
```

## Check and ignore lists
Add an alliance to check:

`INSERT INTO alliance_check_lists VALUES(NULL, {alliance_id});`

Add an individual corp to check:

`INSERT INTO corp_check_lists VALUES(NULL, {corp_id});`

Do not check a corporation, even if it's in a checked alliance or contained within the corp check list:

`INSERT INTO corp_ignore_lists VALUES(NULL, {corp_id});`

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
