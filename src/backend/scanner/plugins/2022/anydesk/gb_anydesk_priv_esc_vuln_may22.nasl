# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:anydesk:anydesk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148542");
  script_version("2022-07-29T04:20:46+0000");
  script_tag(name:"last_modification", value:"2022-07-29 04:20:46 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-29 04:15:29 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:C/A:C");

  script_cve_id("CVE-2022-32450");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("AnyDesk Privilege Escalation Vulnerability (May 2022) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_anydesk_detect_win.nasl");
  script_mandatory_keys("AnyDesk/Win/Installed");

  script_tag(name:"summary", value:"AnyDesk is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"AnyDesk on Windows allows a local user to gain SYSTEM
  privileges via a symbolic link because the user can write to their own %APPDATA% folder (used for
  ad.trace and chat) but the product runs as SYSTEM when writing chat-room data there.");

  script_tag(name:"affected", value:"AnyDesk version 7.0.13 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 29th July, 2022.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2022/Jun/44");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "7.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
