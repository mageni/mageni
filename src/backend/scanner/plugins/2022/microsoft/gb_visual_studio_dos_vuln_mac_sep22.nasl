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

CPE = "cpe:/a:microsoft:visual_studio";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826455");
  script_version("2022-09-15T10:11:07+0000");
  script_cve_id("CVE-2022-38013");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-09-15 10:11:07 +0000 (Thu, 15 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-14 08:52:24 +0530 (Wed, 14 Sep 2022)");
  script_name("Microsoft Visual Studio Denial of Service Vulnerability Sep22 (MACOSX)");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Microsoft Visual Studio September 2022 update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to denial of service
  vulnerability in Visual Studio.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause denial of service condition.");

  script_tag(name:"affected", value:"Visual Studio 2022 prior to version
  17.3.5 on MACOSX");

  script_tag(name:"solution", value:"Update Visual Studio to version Visual
  Studio 2022 17.3.5 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/visualstudio/releases/2022/mac-release-notes");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-38013");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_visual_studio_detect_macosx.nasl");
  script_mandatory_keys("VisualStudio/MacOSX/Version");
  exit(0);
}
include( "host_details.inc" );
include( "version_func.inc" );

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE) ) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.3.4"))
{
  report = report_fixed_ver(installed_version: vers, fixed_version: "Visual Studio 2022 17.3.5", install_path: path);
  security_message(data: report);
  exit(0);
}
exit(99);
