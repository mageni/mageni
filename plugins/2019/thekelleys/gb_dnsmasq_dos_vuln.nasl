# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:thekelleys:dnsmasq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142699");
  script_version("2019-08-06T06:27:10+0000");
  script_tag(name:"last_modification", value:"2019-08-06 06:27:10 +0000 (Tue, 06 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-06 06:07:51 +0000 (Tue, 06 Aug 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-14513");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dnsmasq < 2.76 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("dnsmasq_version.nasl");
  script_mandatory_keys("dnsmasq/installed");

  script_tag(name:"summary", value:"Dnsmasq is prone to an improper bounds checking vulnerability which may lead to
  a denial of service condition.");

  script_tag(name:"insight", value:"An attacker controlled DNS server may send large DNS packets that result in a
  read operation beyond the buffer allocated for the packet.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Dnsmasq versions prior to 2.76.");

  script_tag(name:"solution", value:"Update to version 2.76 or later.");

  script_xref(name:"URL", value:"https://github.com/Slovejoy/dnsmasq-pre2.76");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "2.76")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.76");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
