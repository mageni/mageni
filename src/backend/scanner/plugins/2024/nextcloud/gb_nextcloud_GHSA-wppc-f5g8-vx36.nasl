# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114293");
  script_version("2024-01-29T05:05:18+0000");
  script_tag(name:"last_modification", value:"2024-01-29 05:05:18 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-18 13:56:29 +0000 (Thu, 18 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 21:03:00 +0000 (Fri, 26 Jan 2024)");

  script_cve_id("CVE-2024-22403");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 28.0.0 Improper Authorization Vulnerability (GHSA-wppc-f5g8-vx36)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an improper authorization
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When an attacker would get access to an authorization code they
  could authenticate at any time using the code. Now they are invalidated after 10 minutes and will
  no longer be authenticated.");

  script_tag(name:"affected", value:"Nextcloud Server versions prior to 28.0.0");

  script_tag(name:"solution", value:"Update to version 28.0.0 or later.

  Note: The vendor doesn't plan to fix this flaw in older (supported) server versions like 26 or 27.
  Please see the references for more information.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-wppc-f5g8-vx36");
  script_xref(name:"URL", value:"https://github.com/nextcloud/server/pull/40766");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/discussions/32");

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

if( version_is_less( version: version, test_version: "28.0.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "28.0.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
