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

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127157");
  script_version("2022-08-24T10:46:36+0000");
  script_tag(name:"last_modification", value:"2022-08-24 10:46:36 +0000 (Wed, 24 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-24 09:25:48 +0000 (Wed, 24 Aug 2022)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-28861");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 3.10.6 Information Disclosure Vulnerability (bpo-43223) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An open redirection vulnerability in the HTTP server when an
  URI path starts with '//'.This may lead to information disclosure.");

  script_tag(name:"affected", value:"Python prior to version 3.10.6.");

  script_tag(name:"solution", value:"Update to version 3.10.6 or later.");

  script_xref(name:"URL", value:"https://bugs.python.org/issue43223");
  script_xref(name:"Advisory-ID", value:"bpo-43223");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.10.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
