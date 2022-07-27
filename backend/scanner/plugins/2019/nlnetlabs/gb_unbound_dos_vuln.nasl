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

CPE = "cpe:/a:nlnetlabs:unbound";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143049");
  script_version("2019-10-24T09:33:16+0000");
  script_tag(name:"last_modification", value:"2019-10-24 09:33:16 +0000 (Thu, 24 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-24 09:24:34 +0000 (Thu, 24 Oct 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2019-16866");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unbound DNS Resolver < 1.9.4 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("unbound_version.nasl");
  script_mandatory_keys("unbound/installed");

  script_tag(name:"summary", value:"Unbound DNS Resolver is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unbound accesses uninitialized memory, which allows remote attackers to trigger
  a crash via a crafted NOTIFY query. The source IP address of the query must match an access-control rule.");

  script_tag(name:"affected", value:"Ubound DNS Resolver versions 1.7.1 - 1.9.3.");

  script_tag(name:"solution", value:"Update to version 1.9.4 or later.");

  script_xref(name:"URL", value:"https://nlnetlabs.nl/downloads/unbound/CVE-2019-16866.txt");

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

if (version_in_range(version: version, test_version: "1.7.1", test_version2: "1.9.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.9.4");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
