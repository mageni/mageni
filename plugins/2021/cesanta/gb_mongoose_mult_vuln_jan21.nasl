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

CPE = "cpe:/a:cesanta:mongoose";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145379");
  script_version("2021-02-15T02:58:43+0000");
  script_tag(name:"last_modification", value:"2021-02-15 11:14:46 +0000 (Mon, 15 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-15 02:45:51 +0000 (Mon, 15 Feb 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2021-26528", "CVE-2021-26529", "CVE-2021-26530");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mongoose < 7.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_mongoose_web_server_detect.nasl");
  script_mandatory_keys("Cesanta/Mongoose/installed");

  script_tag(name:"summary", value:"Mongoose is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Out-of-bounds write caused by incorrect error handling of calloc in mg_http_serve_file. (CVE-2021-26528)

  - Out-of-bounds write caused by incorrect error handling of calloc in mg_tls_init. (CVE-2021-26529, CVE-2021-26530)");

  script_tag(name:"affected", value:"Mongoose version 7.0 and prior.");

  script_tag(name:"solution", value:"Update to version 7.1 or later.");

  script_xref(name:"URL", value:"https://github.com/cesanta/mongoose/issues/1201");
  script_xref(name:"URL", value:"https://github.com/cesanta/mongoose/issues/1203");
  script_xref(name:"URL", value:"https://github.com/cesanta/mongoose/issues/1204");

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

if (version_is_less(version: version, test_version: "7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
