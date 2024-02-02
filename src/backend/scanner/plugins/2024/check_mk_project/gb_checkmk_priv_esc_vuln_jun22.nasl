# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:check_mk_project:check_mk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127686");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-17 07:20:26 +0000 (Wed, 17 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-28 14:39:00 +0000 (Tue, 28 Jun 2022)");

  script_cve_id("CVE-2022-33912");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); #nb: Only affects installations done via the Debian packages.

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Checkmk < 1.6.0p29, 2.0.x < 2.0.0p26, 2.1.x < 2.1.0p3 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_check_mk_web_detect.nasl");
  script_mandatory_keys("check_mk/detected");

  script_tag(name:"summary", value:"Checkmk is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Wrong file ownership of the maintainer scripts located at
  /var/lib/dpkg/info: they were owned by the user and group with the ID 1001 instead of root.
  If such a user exists on your system, they can change the content of these files which are later
  executed by root (during package installation, update or removal), leading to a local privilege
  escalation on the monitored host.");

  script_tag(name:"affected", value:"Checkmk installations done via the Debian packages,
  versions prior to 1.6.0p29, 2.0.x prior to 2.0.0p26 and 2.1.x prior to 2.1.0p3.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for steps how to check the
  correct file permissions.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/14098");

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

if( version_is_less( version: version, test_version: "1.6.0p29" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.0.0", test_version_up: "2.0.0p26" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.1.0", test_version_up: "2.1.0p3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
