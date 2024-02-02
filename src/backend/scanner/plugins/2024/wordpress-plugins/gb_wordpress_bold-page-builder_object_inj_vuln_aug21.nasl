# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bold-themes:bold_page_builder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126606");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-04 10:04:50 +0000 (Thu, 04 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-02 15:26:00 +0000 (Thu, 02 Sep 2021)");

  script_cve_id("CVE-2021-24579");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Bold Page Builder Plugin < 3.1.6 Object Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/bold-page-builder/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Bold Page Builder' is prone to an
  object injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The bt_bb_get_grid AJAX action of the plugin passes user input
  into the unserialize() function without any validation or sanitisation, which could lead to a PHP
  Object Injection.");

  script_tag(name:"affected", value:"WordPress Bold Page Builder plugin prior to version 3.1.6.");

  script_tag(name:"solution", value:"Update to version 3.1.6 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/08edce3f-2746-4886-8439-76e44ec76fa8/");

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

if( version_is_less( version: version, test_version: "3.1.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.6", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
