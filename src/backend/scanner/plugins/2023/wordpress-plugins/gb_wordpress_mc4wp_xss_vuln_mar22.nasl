# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mailchimp_for_wordpress_project:mailchimp_for_wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127409");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-04-28 09:08:03 +0000 (Fri, 28 Apr 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-26 19:49:00 +0000 (Thu, 26 May 2022)");

  script_cve_id("CVE-2021-36833");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress MC4WP Plugin < 4.8.7 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/mailchimp-for-wp/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'MC4WP' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not properly sanitise form data, which could
  allow high privilege users to perform cross-site scripting (XSS) attacks when unfiltered_html is
  disallowed.");

  script_tag(name:"affected", value:"WordPress MC4WP plugin prior to version 4.8.7.");

  script_tag(name:"solution", value:"Update to version 4.8.7 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/da04b514-a561-4d25-95b8-1c7b5597f093");

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

if( version_is_less( version: version, test_version: "4.8.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.8.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
