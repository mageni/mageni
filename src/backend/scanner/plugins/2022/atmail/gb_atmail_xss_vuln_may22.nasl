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

CPE = "cpe:/a:atmail:atmail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127016");
  script_version("2022-05-23T12:30:00+0000");
  script_tag(name:"last_modification", value:"2022-05-23 12:30:00 +0000 (Mon, 23 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-19 11:58:33 +0000 (Thu, 19 May 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2022-30776");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Atmail <= 6.5.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("atmail_detect.nasl");
  script_mandatory_keys("Atmail/installed");

  script_tag(name:"summary", value:"Atmail is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"insight", value:"Atmail allows cross-site scripting via the
  index.php/admin/index/ error parameter.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Atmail version 6.5.0 and probably prior.");

  script_tag(name:"solution", value:"No known solution is available as of 19th May, 2022.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://help.atmail.com/hc/en-us/sections/115003283988");
  script_xref(name:"URL", value:"https://medium.com/@bhattronit96/cve-2022-30776-cd34f977c2b9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

ver = infos["version"];
path = infos["location"];

if (version_is_less_equal(version: ver, test_version: "6.5.0")) {
  report = report_fixed_ver(installed_version: ver, fixed_version: "None", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
