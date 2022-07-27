##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pdns_dos1.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# PowerDNS Authoritative Server DoS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140542");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-28 08:39:40 +0700 (Tue, 28 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");

  script_cve_id("CVE-2017-15091");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Authoritative Server DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/authoritative_server/installed");

  script_tag(name:"summary", value:"PowerDNS Authoritative Server is prone to a denial of service
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An issue has been found in the API component of PowerDNS Authoritative,
where some operations that have an impact on the state of the server are still allowed even though the API has
been configured as read-only via the api-readonly keyword. This missing check allows an attacker with valid API
credentials could flush the cache, trigger a zone transfer or send a NOTIFY.");

  script_tag(name:"impact", value:"A remote attacker may cause a parital DoS condition.");

  script_tag(name:"affected", value:"PowerDNS Authoritative up to and including 4.0.4, 3.4.11.");

  script_tag(name:"solution", value:"Upgrade to version 4.0.5 or later.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/authoritative/security-advisories/powerdns-advisory-2017-04.html");

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

if (version_is_less(version: version, test_version: "4.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.5");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(99);
