# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.147858");
  script_version("2022-03-28T09:53:51+0000");
  script_tag(name:"last_modification", value:"2022-03-28 09:53:51 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-28 09:51:08 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2022-27227");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor DoS Vulnerability (2022-01)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor/installed");

  script_tag(name:"summary", value:"PowerDNS Recursor is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"insight", value:"IXFR usually exchanges only the modifications between two
  versions of a zone, but sometimes needs to fall back to a full transfer of the current version.
  When IXFR falls back to a full zone transfer, an attacker in position of man-in-the-middle can
  cause the transfer to be prematurely interrupted. This interrupted transfer is mistakenly
  interpreted as a complete transfer, causing an incomplete zone to be processed.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Recursor version 4.4.7, 4.5.7 and 4.6.0.");

  script_tag(name:"solution", value:"Update to version 4.4.8, 4.5.8, 4.6.1 or later.");

  script_xref(name:"URL", value:"https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2022-01.html");

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

if (version_is_equal(version: version, test_version: "4.4.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.8");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.5.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.8");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.1");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(99);
