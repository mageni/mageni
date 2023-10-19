# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adrotate_banner_manager_project:adrotate_banner_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126476");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-17 10:11:11 +0000 (Thu, 17 Aug 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-02 15:10:00 +0000 (Fri, 02 Dec 2022)");

  script_cve_id("CVE-2022-26366");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress AdRotate Manage Banner Plugin < 5.9.1 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/adrotate/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'AdRotate Manage Banner' is prone to a
  cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not have CSRF checks in some places, which
  could allow attackers to make a logged admin change their password via CSRF attacks.");

  script_tag(name:"affected", value:"WordPress AdRotate Manage Banner prior to version 5.9.1.");

  script_tag(name:"solution", value:"Update to version 5.9.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/19efbad3-d34a-41ac-94c1-2fa2c795dbc0");

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

if( version_is_less( version: version, test_version: "5.9.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.9.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
