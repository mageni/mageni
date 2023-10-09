# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:check_mk_project:check_mk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126468");
  script_version("2023-08-11T16:09:05+0000");
  script_tag(name:"last_modification", value:"2023-08-11 16:09:05 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-11 08:14:26 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2023-31209");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Checkmk 2.0.x < 2.0.0p38, 2.1.x < 2.1.0p32, 2.2.x < 2.2.0p4 Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_check_mk_web_detect.nasl");
  script_mandatory_keys("check_mk/detected");

  script_tag(name:"summary", value:"Checkmk is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Users with the permissions to (a) use the RestAPI, (b) create
  passwords in the password store, and (c) create active checks were able to run arbitrary commands
  on the site.");

  script_tag(name:"affected", value:"Checkmk versions 2.0.x prior to 2.0.0p38, 2.1.x prior to
  2.1.0p32 and 2.2.x prior to 2.2.0p4.");

  script_tag(name:"solution", value:"Update to version 2.0.0p38, 2.1.0p32, 2.2.0p4 or later.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/15194");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version: version, test_version_lo: "2.0.0", test_version_up: "2.0.0p38" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.0p38, 2.1.0p32, 2.2.0p4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.1.0", test_version_up: "2.1.0p32" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.0p32, 2.2.0p4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.2.0", test_version_up: "2.2.0p4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.0p4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
