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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:microsoft:remote_desktop_connection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821276");
  script_version("2022-07-13T12:14:20+0000");
  script_cve_id("CVE-2022-30221");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-07-13 12:14:20 +0000 (Wed, 13 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-13 09:46:45 +0530 (Wed, 13 Jul 2022)");
  script_name("Remote Desktop Client Remote Code Execution Vulnerability (Windows) - July22");

  script_tag(name:"summary", value:"Remote Desktop Client is prone to a remote
  code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an input validation
  error in Windows Graphics Component.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on affected system.");

  script_tag(name:"affected", value:"Remote Desktop Client prior to public
  version 1.2.3317 on Windows");

  script_tag(name:"solution", value:"Update Remote Desktop Client to public
  version 1.2.3317 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/windowsdesktop-whatsnew#updates-for-version-1.2.3317.0");

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_remote_desktop_client_detect_win.nasl");
  script_mandatory_keys("remote/desktop/client/win/detected");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
rdVer = infos['version'];
rdPath = infos['location'];

if(version_is_less(version:rdVer, test_version:"1.2.3317"))
{
  report = report_fixed_ver(installed_version:rdVer, fixed_version:'1.2.3317', install_path:rdPath);
  security_message(data: report);
  exit(0);
}
exit(0);
