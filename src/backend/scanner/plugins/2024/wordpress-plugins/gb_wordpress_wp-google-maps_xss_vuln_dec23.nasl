# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:codecabin:wp_go_maps";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127683");
  script_version("2024-01-18T05:07:09+0000");
  script_tag(name:"last_modification", value:"2024-01-18 05:07:09 +0000 (Thu, 18 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-10 08:10:45 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-11 20:00:00 +0000 (Thu, 11 Jan 2024)");

  script_cve_id("CVE-2023-6627");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Google Maps Plugin < 9.0.28 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-google-maps/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Google Maps' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not properly protect most of its REST API
  routes, which attackers can abuse to store malicious HTML/Javascript on the site.");

  script_tag(name:"affected", value:"WordPress WP Google Maps prior to version 9.0.28.");

  script_tag(name:"solution", value:"Update to version 9.0.28 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/f5687d0e-98ca-4449-98d6-7170c97c8f54/");

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

if( version_is_less( version: version, test_version: "9.0.28" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.0.28", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
