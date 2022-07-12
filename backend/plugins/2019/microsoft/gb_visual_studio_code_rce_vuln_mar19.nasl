# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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

CPE = "cpe:/a:microsoft:visual_studio_code:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814769");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2019-0728");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2019-03-13 19:24:43 +0530 (Wed, 13 Mar 2019)");
  script_name("Microsoft Visual Studio Code Remote Code Execution Vulnerability Mar19");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Security Update March-2019.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in Visual
  Studio Code when it process environment variables after opening a project.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Visual Studio Code before version 1.32");

  script_tag(name:"solution", value:"Update Visual Studio Code to version 1.32
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://code.visualstudio.com/updates/v1_32");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0728");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_visual_studio_code_detect_win.nasl");
  script_mandatory_keys("microsoft_visual_studio_code/version");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE) ) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version: vers, test_version: "1.32"))
{
  report = report_fixed_ver(installed_version: vers, fixed_version: "1.32", install_path: path);
  security_message(data: report, port: 0);
  exit(0);
}
exit(99);
