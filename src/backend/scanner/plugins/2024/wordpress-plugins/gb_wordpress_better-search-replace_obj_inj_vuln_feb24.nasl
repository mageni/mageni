# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:deliciousbrains:better_search_replace";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114329");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-07 16:25:54 +0000 (Wed, 07 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2023-6933");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Better Search Replace Plugin < 1.4.5 PHP Object Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/better-search-replace/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Better Search Replace' is prone to an
  unauthenticated PHP Object Injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is vulnerable to PHP Object Injection via
  deserialization of untrusted input. This makes it possible for unauthenticated attackers to inject
  a PHP Object. No POP chain is present in the vulnerable plugin. If a POP chain is present via an
  additional plugin or theme installed on the target system, it could allow the attacker to delete
  arbitrary files, retrieve sensitive data, or execute code.");

  script_tag(name:"affected", value:"WordPress Better Search Replace plugin prior to version
  1.4.5.");

  script_tag(name:"solution", value:"Update to version 1.4.5 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/better-search-replace/better-search-replace-144-unauthenticated-php-object-injection");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.4.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.4.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
