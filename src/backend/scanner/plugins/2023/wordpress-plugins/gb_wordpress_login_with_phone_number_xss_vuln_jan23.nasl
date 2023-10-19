# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:login_with_phone_number_project:login_with_phone_number";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126463");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-28 12:00:12 +0000 (Mon, 28 Aug 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-27 14:55:00 +0000 (Fri, 27 Jan 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-23492");

  script_name("WordPress Login with Phone Number Plugin < 1.4.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/login-with-phone-number/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Login with Phone Number' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The 'ID' parameter of the 'lwp_forgot_password' action is used
  in the response without any filtering leading to an reflected XSS.");

  script_tag(name:"affected", value:"WordPress Login with Phone Number plugin prior to version
  1.4.2.");

  script_tag(name:"solution", value:"Update to version 1.4.2 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2023-3");

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

if( version_is_less( version: version, test_version: "1.4.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.4.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
