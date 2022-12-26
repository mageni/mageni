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

CPE = "cpe:/a:apache:tapestry";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148988");
  script_version("2022-12-06T10:11:16+0000");
  script_tag(name:"last_modification", value:"2022-12-06 10:11:16 +0000 (Tue, 06 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-05 03:18:39 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2022-46366");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tapestry 3.x RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apache_tapestry_http_detect.nasl");
  script_mandatory_keys("apache/tapestry/detected");

  script_tag(name:"summary", value:"Apache Tapestry is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Apache Tapestry allows deserialization of untrusted data,
  leading to remote code execution.");

  script_tag(name:"affected", value:"Apache Tapestry version 3.x.");

  script_tag(name:"solution", value:"Update to a supported line of Apache Tapestry.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/bwn1vjrvz1hq0wbdzj23wz322244swhj");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version =~ "^3\.") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
