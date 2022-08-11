###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Yammer Desktop Remote Code Execution Vulnerability (Windows)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:microsoft:yammer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814324");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-8569");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-22 11:37:14 +0530 (Thu, 22 Nov 2018)");
  script_name("Microsoft Yammer Desktop Remote Code Execution Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is running Microsoft Yammer Desktop
  and is prone to remote code execution vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the loading of
  arbitrary content in the application.To exploit this vulnerability the attacker
  has to convince the victim to click on a special URL in the application which
  redirects to a compromised webpage. The attacker can gain control of the machine
  upon loading of content from the webpage.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user");

  script_tag(name:"affected", value:"Microsoft Yammer Desktop versions prior to 2.0.0 on Windows");

  script_tag(name:"solution", value:"Upgrade to Microsoft Yammer Desktop 2.0.0 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8569");
  script_xref(name:"URL", value:"https://www.yammer.com/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_yammer_desktop_detect_win.nasl");
  script_mandatory_keys("Microsoft/Yammer/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
yamVer = infos['version'];
yamPath = infos['location'];

if(version_is_less(version:yamVer, test_version:"2.0.0"))
{
  report = report_fixed_ver(installed_version:yamVer, fixed_version:"2.0.0", install_path:yamPath);
  security_message(data:report);
  exit(0);
}
exit(99);
