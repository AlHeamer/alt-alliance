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
	0.5,
	20
);