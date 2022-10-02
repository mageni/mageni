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

CPE = "cpe:/a:nlnetlabs:unbound";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148791");
  script_version("2022-09-30T10:11:44+0000");
  script_tag(name:"last_modification", value:"2022-09-30 10:11:44 +0000 (Fri, 30 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-30 03:10:28 +0000 (Fri, 30 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2022-3204");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unbound DNS Resolver < 1.16.3 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("unbound_version.nasl");
  script_mandatory_keys("unbound/installed");

  script_tag(name:"summary", value:"Unbound DNS Resolver is prone to a denial of service (DoS)
  vulnerability 'Non-Responsive Delegation Attack' (NRDelegation Attack).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The NRDelegation Attack can exploit resolvers by having a
  malicious delegation with a considerable number of non responsive nameservers. It can trigger
  high CPU usage in some resolver implementations that continually look in the cache for resolved
  NS records in that delegation. This can lead to degraded performance and eventually denial of
  service in orchestrated attacks.");

  script_tag(name:"affected", value:"Ubound DNS Resolver version 1.16.2 and prior.");

  script_tag(name:"solution", value:"Update to version 1.16.3 or later.");

  script_xref(name:"URL", value:"https://www.nlnetlabs.nl/downloads/unbound/CVE-2022-3204.txt");

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

if (version_is_less(version: version, test_version: "1.16.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.16.3");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
