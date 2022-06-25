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

CPE = "cpe:/a:phpmailer_project:phpmailer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146144");
  script_version("2021-06-17T09:57:01+0000");
  script_tag(name:"last_modification", value:"2021-06-18 10:19:50 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-17 09:44:26 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-34551");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHPMailer < 6.5.0 RCE Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_phpmailer_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpmailer/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHPMailer is prone to a remote code execution (RCE)
  vulnerability on Windows.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PHPMailer allows remote code execution if lang_path is
  untrusted data and has a UNC pathname.");

  script_tag(name:"affected", value:"PHPMailer prior to version 6.5.0 on Windows.");

  script_tag(name:"solution", value:"Update to version 6.5.1 or later.");

  script_xref(name:"URL", value:"https://github.com/PHPMailer/PHPMailer/blob/master/SECURITY.md");

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

if (version_is_less(version: version, test_version: "6.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.5.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
