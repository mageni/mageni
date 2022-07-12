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

CPE = "cpe:/a:knot-resolver:knot_resolver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143262");
  script_version("2019-12-18T03:39:51+0000");
  script_tag(name:"last_modification", value:"2019-12-18 03:39:51 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-18 03:30:41 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2019-19331");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Knot Resolver < 4.3.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_knot_resolver_detect.nasl");
  script_mandatory_keys("knot/resolver/detected");

  script_tag(name:"summary", value:"Knot Resolver is prone to a denial of service vulnerability through high
  CPU utilization.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"DNS replies with very many resource records might be processed very
  inefficiently, in extreme cases taking even several CPU seconds for each such uncached message. For example, a
  few thousand A records can be squashed into one DNS message (limit is 64kB).");

  script_tag(name:"affected", value:"Knot Resolver prior to version 4.3.0.");

  script_tag(name:"solution", value:"Update to version 4.3.0.");

  script_xref(name:"URL", value:"https://www.knot-resolver.cz/2019-12-04-knot-resolver-4.3.0.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.0", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
