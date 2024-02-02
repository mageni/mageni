# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:check_mk_project:check_mk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124476");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-17 09:14:26 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-30 21:00:00 +0000 (Thu, 30 Nov 2023)");

  script_cve_id("CVE-2023-6156", "CVE-2023-6157", "CVE-2023-6251", "CVE-2023-23549");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Checkmk 2.0.x < 2.1.0p37, 2.2.x < 2.2.0p15 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_check_mk_web_detect.nasl");
  script_mandatory_keys("check_mk/detected");

  script_tag(name:"summary", value:"Checkmk is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-6156: An arbitrary livestatus command execution due to improper neutralization of
  livestatus command delimiters in the availability timeline.

  - CVE-2023-6157: An arbitrary livestatus command execution due to improper neutralization of
  livestatus command delimiters in ajax_search.

  - CVE-2023-6251: An authenticated attacker could craft a link with the generated message uuid to
  delete the message via send user message.

  - CVE-2023-23549: It was possible to create Hosts with arbitrary length. Since
  Checkmk stores information in files which paths contain the hostname these path could exceed the
  allowed length leading to various errors to an extend that rendered the usage of parts of the GUI
  useless.");

  script_tag(name:"affected", value:"Checkmk versions 2.0.x prior to 2.1.0p37 and 2.2.x prior to
  2.2.0p15.");

  script_tag(name:"solution", value:"Update to version 2.1.0p37, 2.2.0p15, 2.3.0b1 or later.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/16219");
  script_xref(name:"URL", value:"https://checkmk.com/werk/16221");
  script_xref(name:"URL", value:"https://checkmk.com/werk/16224");

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

if( version_in_range_exclusive( version: version, test_version_lo: "2.0", test_version_up: "2.1.0p37" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.0p37, 2.2.0p15, 2.3.0b1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.2.0", test_version_up: "2.2.0p15" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.0p15, 2.3.0b1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
