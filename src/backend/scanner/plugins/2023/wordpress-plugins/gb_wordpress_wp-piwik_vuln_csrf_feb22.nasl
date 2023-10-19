# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wp-piwik_project:wp-piwik";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124432");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-12 10:11:11 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP-Matomo Integration Plugin < 1.0.27 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-piwik/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP-Matomo Integration' is prone to a
  cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin due to missing nonce validation on the show() makes
  it possible for unauthenticated attackers to modify an affected sites settings via a forged
  request granted they can trick a site administrator into performing an action such as clicking on
  a link.");

  script_tag(name:"affected", value:"WordPress WP-Matomo Integration prior to version 1.0.27.");

  script_tag(name:"solution", value:"Update to version 1.0.27 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-piwik/wp-matomo-integration-wp-piwik-1026-cross-site-request-forgery");

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

if( version_is_less( version: version, test_version: "1.0.27" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.0.27", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
