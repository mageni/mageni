# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:kentico:cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143408");
  script_version("2020-01-28T03:03:15+0000");
  script_tag(name:"last_modification", value:"2020-01-28 03:03:15 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-28 02:59:59 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-19493");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kentico < 12.0.50 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kentico_cms_detect.nasl");
  script_mandatory_keys("kentico_cms/detected");

  script_tag(name:"summary", value:"Kentico allows file uploads in which the Content-Type header is inconsistent
  with the file extension, leading to XSS.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Kentico prior to version 12.0.50.");

  script_tag(name:"solution", value:"Update to version 12.0.50 or later.");

  script_xref(name:"URL", value:"https://devnet.kentico.com/download/hotfixes#securityBugs-v12");

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

if (version_is_less(version: version, test_version: "12.0.50")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.0.50", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
