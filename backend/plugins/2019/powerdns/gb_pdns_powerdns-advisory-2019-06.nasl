# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = 'cpe:/a:powerdns:authoritative_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142678");
  script_version("2019-07-31T01:58:08+0000");
  script_tag(name:"last_modification", value:"2019-07-31 01:58:08 +0000 (Wed, 31 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-31 01:48:25 +0000 (Wed, 31 Jul 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2019-10203");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("PowerDNS Authoritative Server Denial of Service Vulnerability (2019-06)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/authoritative_server/installed");

  script_tag(name:"summary", value:"PowerDNS Authoritative Server is prone to a denial of service vulnerability
  via crafted zone records.");

  script_tag(name:"insight", value:"An issue has been found in PowerDNS Authoritative Server allowing an
  authorized user to cause the server to exit by inserting a crafted record in a MASTER type zone under their
  control. The issue is due to the fact that the Authoritative Server will exit when it tries to store the
  notified serial in the PostgreSQL database, if this serial cannot be represented in 31 bits.

  Note: Just installations using PostgreSQL as a backend are affected.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Authoritative 4.1.10 and prior. Although the advisory is stating
  that version 4.0.9 and 4.1.11 are not affected they still might be vulnerable if the mitigation steps are not
  applied.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for mitigation steps.");

  script_xref(name:"URL", value:"https://docs.powerdns.com/authoritative/security-advisories/powerdns-advisory-2019-06.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "4.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(0);
