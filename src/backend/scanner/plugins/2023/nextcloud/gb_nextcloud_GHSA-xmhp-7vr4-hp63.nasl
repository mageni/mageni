# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124446");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-17 09:53:11 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-20 12:19:00 +0000 (Fri, 20 Oct 2023)");

  script_cve_id("CVE-2023-45148");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 22.2.10.16, 23.x < 23.0.12.11, 24.x < 24.0.12.7, 25.x < 25.0.11, 26.x < 26.0.6, 27.x < 27.1.0 Improper Access Control Vulnerability (GHSA-xmhp-7vr4-hp63)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an improper access control
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When Memcached is used as memcache.distributed the rate limiting
  in Nextcloud Server could be reset unexpectingly resetting the rate count earlier than
  intended.");

  script_tag(name:"affected", value:"Nextcloud Server version 22.x prior to 22.2.10.16, 23.x prior
  to 23.0.12.11, 24.x prior to 24.0.12.7, 25.x prior to 25.0.11, 26.x prior to 26.0.6 and 27.x prior
  to 27.1.0.");

  script_tag(name:"solution", value:"Update to version 22.2.10.16, 23.0.12.11, 24.0.12.7, 25.0.11,
  26.0.6, 27.1.0 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-xmhp-7vr4-hp63");

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

if( version_is_less( version: version, test_version: "22.2.10.16" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "22.2.10.16 (Nextcloud Enterprise only)", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "23.0", test_version_up: "23.0.12.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "23.0.12.11 (Nextcloud Enterprise only)", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "24.0", test_version_up: "24.0.12.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "24.0.12.7 (Nextcloud Enterprise only)", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "25.0", test_version_up: "25.0.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "25.0.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "26.0", test_version_up: "26.0.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "26.0.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "27.0", test_version_up: "27.1.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "27.1.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
