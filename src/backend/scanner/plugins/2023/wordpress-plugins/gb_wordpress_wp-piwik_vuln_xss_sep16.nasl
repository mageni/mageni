# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wp-piwik_project:wp-piwik";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124433");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-12 10:11:11 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP-Matomo Integration Plugin < 1.0.11 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-piwik/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP-Matomo Integration' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Plugin due to insufficient input sanitization and output escaping.
  Makes it possible for [authentication-level] attackers [inject user-level requirements if available
  and authentication is required] to inject arbitrary web scripts in pages that will execute
  whenever a user accesses an injected page.");

  script_tag(name:"affected", value:"WordPress WP-Matomo Integration prior to version 1.0.11.");

  script_tag(name:"solution", value:"Update to version 1.0.11 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-piwik/wp-matomo-integration-wp-piwik-1011-unauthenticated-stored-cross-site-scripting");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.0.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.0.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
