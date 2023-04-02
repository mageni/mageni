# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:check_mk_project:check_mk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127369");
  script_version("2023-03-27T10:09:49+0000");
  script_tag(name:"last_modification", value:"2023-03-27 10:09:49 +0000 (Mon, 27 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-21 11:21:26 +0000 (Tue, 21 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2023-22288");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Checkmk 2.0.x < 2.0.0p35, 2.1.x < 2.1.0p25, 2.2.x < 2.2.0b1, 2.3.x < 2.3.0b1 HTML Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_check_mk_web_detect.nasl");
  script_mandatory_keys("check_mk/detected");

  script_tag(name:"summary", value:"Checkmk is prone to an HTML injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Attackers with permissions to configure HTML notifications are
  able to inject HTML into E-Mails via Insert HTML section between body and table.");

  script_tag(name:"affected", value:"Checkmk versions 1.6.0 (EOL), 2.0.x prior to 2.0.0p35, 2.1.x
  prior to 2.1.0p25, 2.2.x prior to 2.2.0b1 and 2.3.x prior to 2.3.0b1.");

  script_tag(name:"solution", value:"Update to version 2.0.0p35, 2.1.0p25, 2.2.0b1, 2.3.0b1
  or later.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/15069");

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

if(version_is_less_equal( version: version, test_version: "1.6.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.0p35", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.0.0", test_version_up: "2.0.0p35" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.0p35, 2.1.0p25, 2.2.0b1, 2.3.0b1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.1.0", test_version_up: "2.1.0p25" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.0p25, 2.2.0b1, 2.3.0b1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.2.0", test_version_up: "2.2.0b1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.0b1, 2.3.0b1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.3.0", test_version_up: "2.3.0b1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.3.0b1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
