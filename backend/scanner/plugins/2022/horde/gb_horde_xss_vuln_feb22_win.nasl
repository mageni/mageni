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

CPE = "cpe:/a:horde:horde_groupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147705");
  script_version("2022-02-28T02:54:24+0000");
  script_tag(name:"last_modification", value:"2022-02-28 11:04:36 +0000 (Mon, 28 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-28 02:53:29 +0000 (Mon, 28 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Horde Groupware Webmail <= 5.2.22 XSS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("horde_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("horde/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Horde Groupware Webmail is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"insight", value:"An attacker can craft an OpenOffice document that when
  transformed to XHTML by Horde for preview can execute a malicious JavaScript payload. The
  vulnerability triggers when a targeted user views an attached OpenOffice document in the browser.");

  script_tag(name:"impact", value:"An attacker can steal all emails the victim has sent and
  received.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Horde Groupware Webmail version 5.2.22 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 28th February, 2022.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://blog.sonarsource.com/horde-webmail-account-takeover-via-email");

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

if (version_is_less_equal(version: version, test_version: "5.2.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
