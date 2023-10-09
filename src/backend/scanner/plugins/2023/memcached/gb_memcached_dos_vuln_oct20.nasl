# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:memcached:memcached";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126462");
  script_version("2023-08-25T05:06:04+0000");
  script_tag(name:"last_modification", value:"2023-08-25 05:06:04 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-23 10:30:42 +0000 (Wed, 23 Aug 2023)");
  script_tag(name:"cvss_base", value:"2.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2022-48571");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Memcached 1.6.x < 1.6.8 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_memcached_detect.nasl", "gb_memcached_detect_udp.nasl");
  script_mandatory_keys("memcached/detected");

  script_tag(name:"summary", value:"Memcached is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Remote attacker is able to cause a denial of service via
  multi-packet uploads in UDP.");

  script_tag(name:"affected", value:"Memcached version 1.6.x prior to 1.6.8.");

  script_tag(name:"solution", value:"Update to version 1.6.8 or later.");

  script_xref(name:"URL", value:"https://github.com/memcached/memcached/wiki/ReleaseNotes168");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_proto( cpe: CPE, port: port ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];

if ( version_in_range_exclusive( version: version, test_version_lo: "1.6.0", test_version_up: "1.6.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.6.8" );
  security_message( port: port, proto: proto, data: report );
  exit( 0 );
}

exit( 99 );
