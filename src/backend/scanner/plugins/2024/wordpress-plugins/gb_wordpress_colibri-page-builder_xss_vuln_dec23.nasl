# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:extendthemes:colibri_page_builder";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126560");
  script_version("2024-01-12T05:05:56+0000");
  script_tag(name:"last_modification", value:"2024-01-12 05:05:56 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-03 05:00:45 +0000 (Wed, 03 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-29 05:54:00 +0000 (Fri, 29 Dec 2023)");

  script_cve_id("CVE-2023-50833");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Colibri Page Builder Plugin < 1.0.241 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/colibri-page-builder/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Colibri Page Builder' is prone to a
  cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Stored cross-site scripting (XSS), due to insufficient input
  sanitization and output escaping.");

  script_tag(name:"affected", value:"WordPress Colibri Page Builder prior to version 1.0.241.");

  script_tag(name:"solution", value:"Update to version 1.0.241 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/colibri-page-builder/colibri-page-builder-10239-authenticated-contributor-stored-cross-site-scripting-via-shortcode");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version: version, test_version: "1.0.241" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.0.241", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
