# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:templately:templately";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127616");
  script_version("2023-11-16T05:05:14+0000");
  script_tag(name:"last_modification", value:"2023-11-16 05:05:14 +0000 (Thu, 16 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-09 12:30:07 +0000 (Thu, 09 Nov 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 15:32:00 +0000 (Tue, 14 Nov 2023)");

  script_cve_id("CVE-2023-5454");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Templately - Gutenberg & Elementor Template Library Plugin < 2.2.6 Missing Authorization Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/templately/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Templately - Gutenberg & Elementor
  Template Library' is prone to a missing authorization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not properly authorize the
  'saved-templates/delete' REST API call, allowing unauthenticated users to delete arbitrary
  posts.");

  script_tag(name:"affected", value:"WordPress Templately - Gutenberg & Elementor Template Library
  plugin prior to version 2.2.6.");

  script_tag(name:"solution", value:"Update to version 2.2.6 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/1854f77f-e12a-4370-9c44-73d16d493685/");

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

if( version_is_less( version: version, test_version: "2.2.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
