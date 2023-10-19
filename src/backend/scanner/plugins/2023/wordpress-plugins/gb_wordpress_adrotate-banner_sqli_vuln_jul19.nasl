# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adrotate_banner_manager_project:adrotate_banner_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127584");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-12 12:39:11 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-31 08:15:00 +0000 (Wed, 31 Jul 2019)");

  script_cve_id("CVE-2019-13570");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress AdRotate Manage Banner Plugin < 5.3 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/adrotate/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'AdRotate Manage Banner' is prone to an
  SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not properly sanitise and escape some
  parameters before using them in an SQL statement.");

  script_tag(name:"affected", value:"WordPress AdRotate Manage Banner prior to version 5.3.");

  script_tag(name:"solution", value:"Update to version 5.3 or later.");

  script_xref(name:"URL", value:"https://ajdg.solutions/2019/07/11/adrotate-pro-5-3-important-update-for-security-and-ads-txt/");

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

if( version_is_less( version: version, test_version: "5.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
