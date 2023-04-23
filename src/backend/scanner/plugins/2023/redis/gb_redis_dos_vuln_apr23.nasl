# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127401");
  script_version("2023-04-20T07:50:57+0000");
  script_tag(name:"last_modification", value:"2023-04-20 07:50:57 +0000 (Thu, 20 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-19 14:40:38 +0000 (Wed, 19 Apr 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2023-28856");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis < 6.0.19, 6.2.x < 6.2.12, 7.0.x < 7.0.11 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Authenticated users can use the HINCRBYFLOAT command to create
  an invalid hash field that may later crash Redis on access.");

  script_tag(name:"affected", value:"Redis versions prior to 6.0.19, 6.2.x prior to 6.2.12 and
  7.0.x prior to 7.0.11.");

  script_tag(name:"solution", value:"Update to version 6.0.19, 6.2.12, 7.0.11 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-hjv8-vjf6-wcr6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if( version_is_less( version: version, test_version: "6.0.19" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.0.19" );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "6.2.0", test_version_up: "6.2.12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.2.12" );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "7.0.0", test_version_up: "7.0.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.11" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
