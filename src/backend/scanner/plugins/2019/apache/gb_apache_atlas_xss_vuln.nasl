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

CPE = "cpe:/a:apache:atlas";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143175");
  script_version("2019-11-26T03:50:16+0000");
  script_tag(name:"last_modification", value:"2019-11-26 03:50:16 +0000 (Tue, 26 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-26 03:35:41 +0000 (Tue, 26 Nov 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-10070");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Atlas XSS Vulnerability - Nov19");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_atlas_detect.nasl");
  script_mandatory_keys("Apache/Atlas/Installed");

  script_tag(name:"summary", value:"Apache Atlas is prone to a stored cross-site scripting vulnerability in the
  search functionality.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Atlas versions 0.8.3 and 1.1.0.");

  script_tag(name:"solution", value:"Upgrade to Version 0.8.4, 1.2.0 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/cc21437c4c5053a13e13332d614d5172f39da03491fe17ae260be221@%3Cdev.atlas.apache.org%3E");

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

if (version_is_equal(version: version, test_version: "0.8.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.8.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "1.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
