# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:check_mk_project:check_mk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127435");
  script_version("2023-05-22T12:17:59+0000");
  script_tag(name:"last_modification", value:"2023-05-22 12:17:59 +0000 (Mon, 22 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-18 07:21:26 +0000 (Thu, 18 May 2023)");
  script_tag(name:"cvss_base", value:"8.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:C/A:C");

  script_cve_id("CVE-2023-31208");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Checkmk 2.0.x < 2.0.p36, 2.1.x < 2.1.0p28, 2.2.x < 2.2.0b8 Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_check_mk_web_detect.nasl");
  script_mandatory_keys("check_mk/detected");

  script_tag(name:"summary", value:"Checkmk is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"All RestAPI endpoints that use Livestatus filter operators are
  susceptible to injection of Livestatus commands.");

  script_tag(name:"affected", value:"Checkmk versions 2.0.x prior to 2.0.0p36, 2.1.x prior to
  2.1.0p28 and 2.2.x prior to 2.2.0b8.");

  script_tag(name:"solution", value:"Update to version 2.0.0p36, 2.1.0p28, 2.2.0b8, 2.3.0b1
  or later.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/15191");

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

if( version_in_range_exclusive( version: version, test_version_lo: "2.0.0", test_version_up: "2.0.0p36" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.0p36", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.1.0", test_version_up: "2.1.0p28" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.0p28", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.2.0", test_version_up: "2.2.0b8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.0b8, 2.3.0b1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );

}
exit( 99 );
