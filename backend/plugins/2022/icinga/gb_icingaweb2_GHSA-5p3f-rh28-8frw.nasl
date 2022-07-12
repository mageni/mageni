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

CPE = "cpe:/a:icinga:icingaweb2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170044");
  script_version("2022-03-25T14:06:01+0000");
  script_tag(name:"last_modification", value:"2022-03-28 10:01:15 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-09 12:28:35 +0000 (Wed, 09 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-14 13:45:00 +0000 (Mon, 14 Mar 2022)");

  script_cve_id("CVE-2022-24716");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Icinga Web 2 2.9.x < 2.9.6 Path Traversal Vulnerability - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_icinga_icingaweb2_consolidation.nasl");
  script_mandatory_keys("icinga/icingaweb2/detected");

  script_tag(name:"summary", value:"Icinga Web 2 is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unauthenticated users can leak the contents of files of the
  local system accessible to the web-server user, including icingaweb2 configuration files with
  database credentials.");

  script_tag(name:"affected", value:"Icinga Web 2 version 2.9.x through 2.9.5.");

  script_tag(name:"solution", value:"Update to version 2.9.6 or later.");

  script_xref(name:"URL", value:"https://github.com/Icinga/icingaweb2/security/advisories/GHSA-5p3f-rh28-8frw");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version:version, test_version:"2.9.0", test_version2:"2.9.5")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.9.6", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
