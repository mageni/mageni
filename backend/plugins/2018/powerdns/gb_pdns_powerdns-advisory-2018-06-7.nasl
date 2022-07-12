##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pdns_powerdns-advisory-2018-06-7.nasl 13427 2019-02-04 08:52:52Z mmartin $
#
# PowerDNS Recursor Multiple DoS Vulnerabilities
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

CPE = 'cpe:/a:powerdns:recursor';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141656");
  script_version("$Revision: 13427 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-04 09:52:52 +0100 (Mon, 04 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-11-07 09:59:29 +0700 (Wed, 07 Nov 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2018-14626", "CVE-2018-14644");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor Multiple DoS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor/installed");

  script_tag(name:"summary", value:"PowerDNS Recursor is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PowerDNS Recursor is prone to multiple denial of service vulnerabilities:

  - Packet cache pollution via crafted query (CVE-2018-14626)

  - Crafted query for meta-types can cause a denial of service (CVE-2018-14644)");

  script_tag(name:"affected", value:"PowerDNS Recursor versions 4.0.0 until 4.1.4.");

  script_tag(name:"solution", value:"Upgrade to version 4.0.9, 4.1.5 or later.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2018-06.html");
  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2018-07.html");

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

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.9");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.1", test_version2: "4.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.5");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(0);
