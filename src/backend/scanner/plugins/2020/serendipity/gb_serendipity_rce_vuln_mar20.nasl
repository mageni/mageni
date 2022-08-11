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

CPE = "cpe:/a:s9y:serendipity";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143659");
  script_version("2020-03-31T02:25:56+0000");
  script_tag(name:"last_modification", value:"2020-03-31 10:13:50 +0000 (Tue, 31 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-31 02:18:43 +0000 (Tue, 31 Mar 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-10964");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Serendipity < 2.3.4 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("serendipity_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Serendipity/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Serendipity on Windows is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Serendipity on Windows allows remote attackers to execute arbitrary code
  because the filename of a renamed file may end with a dot. This file may then be renamed to have a .php filename.");

  script_tag(name:"affected", value:"Serendipity versions before 2.3.4 on Windows.");

  script_tag(name:"solution", value:"Update to version 2.3.4 or later.");

  script_xref(name:"URL", value:"https://blog.s9y.org/archives/290-Serendipity-2.3.4-released-security-update.html");
  script_xref(name:"URL", value:"https://github.com/s9y/Serendipity/releases/tag/2.3.4");

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

if (version_is_less(version: version, test_version: "2.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.4", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
