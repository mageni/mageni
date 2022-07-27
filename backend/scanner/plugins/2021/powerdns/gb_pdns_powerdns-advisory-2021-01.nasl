# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:powerdns:authoritative_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146382");
  script_version("2021-07-27T02:37:05+0000");
  script_tag(name:"last_modification", value:"2021-07-27 02:37:05 +0000 (Tue, 27 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-27 02:31:35 +0000 (Tue, 27 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2021-36754");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Authoritative Server DoS Vulnerability (2021-01)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/authoritative_server/installed");

  script_tag(name:"summary", value:"PowerDNS Authoritative Server is prone to a denial of service
  (DoS) vulnerability.");

  script_tag(name:"insight", value:"PowerDNS Authoritative Server will crash with an uncaught out
  of bounds exception if it receives a query with QTYPE 65535.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Authoritative version 4.5.0.");

  script_tag(name:"solution", value:"Update to version 4.5.1 or later.");

  script_xref(name:"URL", value:"https://blog.powerdns.com/2021/07/26/security-advisory-2021-01-for-powerdns-authoritative-server-4-5-0/");

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

if (version =~ "^4\.5\.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.1");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(99);
