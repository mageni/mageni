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

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145663");
  script_version("2021-03-29T04:06:56+0000");
  script_tag(name:"last_modification", value:"2021-03-29 10:41:25 +0000 (Mon, 29 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-29 03:57:55 +0000 (Mon, 29 Mar 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-28133");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_tag(name:"qod_type", value:"registry");

  script_name("Zoom Client Screen Sharing Vulnerability (Mar 2021) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_zoom_client_detect_win.nasl");
  script_mandatory_keys("zoom/client/win/detected");

  script_tag(name:"summary", value:"The Zoom Client is prone to a vulnerability in the Application Window
  Screen Sharing Functionality.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Zoom sometimes allows attackers to read private information on a
  participant's screen, even though the participant never attempted to share the private part of their screen.
  When a user shares a specific application window via the Share Screen functionality, other meeting
  participants can briefly see contents of other application windows that were explicitly not shared. The
  contents of these other windows can (for instance) be seen for a short period of time when they overlay the
  shared window and get into focus. (An attacker can, of course, use a separate screen-recorder application,
  unsupported by Zoom, to save all such contents for later replays and analysis.) Depending on the
  unintentionally shared data, this short exposure of screen contents may be a more or less severe security
  issue.");

  script_tag(name:"affected", value:"Any version of Zoom Client on Windows.");

  script_tag(name:"solution", value:"No known solution is available as of 29th March, 2021.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://zoom.us/trust/security/security-bulletin");
  script_xref(name:"URL", value:"https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2020-044.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
security_message(port: 0, data: report);
exit(0);
