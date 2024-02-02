# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:check_mk_project:check_mk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126641");
  script_version("2024-01-19T16:09:33+0000");
  script_tag(name:"last_modification", value:"2024-01-19 16:09:33 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-12 11:48:26 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-19 02:12:00 +0000 (Fri, 19 Jan 2024)");

  script_cve_id("CVE-2023-6735", "CVE-2023-6740", "CVE-2023-31211");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Checkmk < 2.1.0p38, 2.2.x < 2.2.0p18 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_check_mk_web_detect.nasl");
  script_mandatory_keys("check_mk/detected");

  script_tag(name:"summary", value:"Checkmk is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-6735: By crafting a malicious command that then shows up in the output of ps users of
  monitored hosts could gain root privileges. This was achieved by exploiting the insufficient
  quoting when using ksh's eval to create the required environment.

  - CVE-2023-6740: A malicious oracle user could replace the jarsigner binary with another script
  and put it in the JAVA_HOME directory. The script would be executed by the root user.

  - CVE-2023-31211: Automation user whose password was disabled also described as 'disable the
  login to this account' was still able to authenticate. The information that a user was disabled
  was not checked for automation users.");

  script_tag(name:"affected", value:"Checkmk versions prior to 2.1.0p38 and 2.2.x prior to
  2.2.0p18.");

  script_tag(name:"solution", value:"Update to version 2.1.0p38, 2.2.0p18 or later.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/16273");
  script_xref(name:"URL", value:"https://checkmk.com/werk/16163");
  script_xref(name:"URL", value:"https://checkmk.com/werk/16227");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.1.0p38" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.0p38", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.2.0", test_version_up: "2.2.0p18" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.0p18", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
