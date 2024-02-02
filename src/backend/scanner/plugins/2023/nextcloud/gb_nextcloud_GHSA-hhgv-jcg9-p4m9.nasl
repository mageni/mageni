# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124445");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-17 08:57:11 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-20 12:18:00 +0000 (Fri, 20 Oct 2023)");

  script_cve_id("CVE-2023-45151");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server 25.x < 25.0.8, 26.x < 26.0.3, 27.x < 27.0.1 Improper Access Control Vulnerability (GHSA-hhgv-jcg9-p4m9)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an improper access control
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"When an attacker got access to the database or a backup of the
  database they could use the client secrets to use the OAuth2 logins on third party services linked
  with the Nextcloud server.");

  script_tag(name:"affected", value:"Nextcloud Server version 25.x prior to 25.0.8, 26.x prior to
  26.0.3 and 27.x prior to 27.0.1.");

  script_tag(name:"solution", value:"Update to version 25.0.8, 26.0.3, 27.0.1 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-hhgv-jcg9-p4m9");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

# nb: GHSA-2hrc-5fgp-c9c9 and GHSA-xmhp-7vr4-hp63 published at the same had mentioned 22.0.x as the
# "lower" bound of the relevant vulnerability so we're assuming here that 25.0+ for this specific
# flaw was only affected as otherwise the vendor would have marked 22.0.x here as affected as well.
if( version_in_range_exclusive( version: version, test_version_lo: "25.0", test_version_up: "25.0.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "25.0.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "26.0", test_version_up: "26.0.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "26.0.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "27.0", test_version_up: "27.0.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "27.0.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
