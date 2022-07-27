##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pdns_powerdns-advisory-2016-03.nasl 13394 2019-02-01 07:36:10Z mmartin $
#
# PowerDNS Authoritative Server < 3.4.11 / 4.0 < 4.0.2 DoS Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = 'cpe:/a:powerdns:authoritative_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141466");
  script_version("$Revision: 13394 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-01 08:36:10 +0100 (Fri, 01 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-09-11 10:27:37 +0700 (Tue, 11 Sep 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2016-7072", "CVE-2016-2120");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Authoritative Server < 3.4.11 / 4.0 < 4.0.2 DoS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/authoritative_server/installed");

  script_tag(name:"summary", value:"An issue has been found in PowerDNS Authoritative Server allowing a remote,
unauthenticated attacker to cause a denial of service by opening a large number of TCP connections to the web
server. If the web server runs out of file descriptors, it triggers an exception and terminates the whole PowerDNS
process. While it's more complicated for an unauthorized attacker to make the web server run out of file
descriptors since its connection will be closed just after being accepted, it might still be possible.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Authoritative Server version 3.4.10, 4.0.1 and prior.");

  script_tag(name:"solution", value:"Upgrade to version 3.4.11, 4.0.2 or later.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2016-03/");
  script_xref(name:"URL", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2016-05/");

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

if (version_is_less(version: version, test_version: "3.4.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.11");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.2");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(0);