##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_isc_bind_dos_vuln08.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# ISC BIND Denial of Service Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:isc:bind";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106291");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-28 09:42:23 +0700 (Wed, 28 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_cve_id("CVE-2016-2776");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("bind_version.nasl");
  script_mandatory_keys("ISC BIND/installed");

  script_tag(name:"summary", value:"ISC BIND is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A crafted query could crash the BIND name server daemon, leading to a
denial of service. All server roles (authoritative, recursive and forwarding) in default configurations are
affected.");

  script_tag(name:"impact", value:"An remote attacker may cause a denial of service condition.");

  script_tag(name:"affected", value:"BIND 9");

  script_tag(name:"solution", value:"Upgrade to 9.9.9-P3, 9.9.9-S5, 9.10.4-P3, 9.11.0rc3 or later.");

  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01419");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("revisions-lib.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if (version !~ "^9\.")
  exit(99);

if (version =~ "9\.9\.[3-9]\.S[0-9]") {
  if (version_is_less(version: version, test_version: "9.9.9.S5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.9.9-S5");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_is_less(version: version, test_version: "9.9.9.P3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.9.9-P3");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.10.0", test_version2: "9.10.4.P2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.10.4-P3");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if ((revcomp(a: version, b: "9.11.0a1") >= 0) && (revcomp(a: version, b: "9.11.0rc1") <= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.0rc3");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
