# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:nic:knot_resolver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149342");
  script_version("2023-02-23T10:09:02+0000");
  script_tag(name:"last_modification", value:"2023-02-23 10:09:02 +0000 (Thu, 23 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-22 03:09:58 +0000 (Wed, 22 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2023-26249");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Knot Resolver < 5.6.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_knot_resolver_detect.nasl");
  script_mandatory_keys("knot/resolver/detected");

  script_tag(name:"summary", value:"Knot Resolver is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Knot Resolver enables attackers to consume its resources,
  launching amplification attacks and potentially causing a denial of service. Specifically, a
  single client query may lead to a hundred TCP connection attempts if a DNS server closes
  connections without providing a response.");

  script_tag(name:"affected", value:"Knot Resolver prior to version 5.6.0.");

  script_tag(name:"solution", value:"Update to version 5.6.0 or later.");

  script_xref(name:"URL", value:"https://www.knot-resolver.cz/2023-01-26-knot-resolver-5.6.0.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.0", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
