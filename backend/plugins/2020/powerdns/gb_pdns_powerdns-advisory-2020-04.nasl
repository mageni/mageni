# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:powerdns:recursor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144214");
  script_version("2020-07-03T08:10:33+0000");
  script_tag(name:"last_modification", value:"2020-07-03 10:14:24 +0000 (Fri, 03 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-03 08:03:43 +0000 (Fri, 03 Jul 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-14196");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor < 4.1.17, 4.2.0 < 4.2.3, 4.3.0 < 4.3.2 Access Restriction Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor/installed");

  script_tag(name:"summary", value:"PowerDNS Recursor is prone to an access restriction bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An issue has been found in PowerDNS Recursor where the ACL applied to
  the internal web server via webserver-allow-from is not properly enforced, allowing a remote attacker to
  send HTTP queries to the internal web server, bypassing the restriction.

  In the default configuration the API webserver is not enabled. Only installations using a non-default
  value for webserver and webserver-address are affected.");

  script_tag(name:"affected", value:"PowerDNS Recursor 4.1.16 and prior, 4.2.0 - 4.2.2 and 4.3.0 - 4.3.1.");

  script_tag(name:"solution", value:"Update to version 4.1.17, 4.2.3, 4.3.2 or later.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2020-04.html");

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

if (version_is_less(version: version, test_version: "4.1.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.17");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.2.0", test_version2: "4.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.3");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.0", test_version2: "4.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.2");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(99);
