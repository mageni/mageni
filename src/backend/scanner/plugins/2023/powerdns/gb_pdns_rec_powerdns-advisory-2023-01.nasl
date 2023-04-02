# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:powerdns:recursor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118454");
  script_version("2023-03-31T10:08:38+0000");
  script_tag(name:"last_modification", value:"2023-03-31 10:08:38 +0000 (Fri, 31 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-01-23 14:31:57 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:C");

  script_cve_id("CVE-2023-22617");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor DoS Vulnerability (2023-01)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor/installed");

  script_tag(name:"summary", value:"PowerDNS Recursor is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An issue in the processing of queries for misconfigured domains
  has been found in PowerDNS Recursor 4.8.0, allowing a remote attacker to crash the recursor by
  sending a DNS query for one of these domains. The issue happens because the recursor enters an
  unbounded loop, exceeding its stack memory. Because of the specific way in which this issue
  happens, the vendor does not believe this issue to be exploitable for code execution.

  Note: PowerDNS Recursor versions before 4.8.0 are not affected.

  Note that when the PowerDNS Recursor is run inside a supervisor like supervisord or systemd, a
  crash will lead to an automatic restart, limiting the impact to a somewhat degraded service.");

  script_tag(name:"affected", value:"PowerDNS Recursor version 4.8.0.");

  script_tag(name:"solution", value:"Update to version 4.8.1 or later.");

  script_xref(name:"URL", value:"https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2023-01.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_in_range_exclusive( version:version, test_version_lo:"4.8.0", test_version_up:"4.8.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.8.1" );
  security_message( port:port, proto:proto, data:report );
  exit( 0 );
}

exit( 99 );
