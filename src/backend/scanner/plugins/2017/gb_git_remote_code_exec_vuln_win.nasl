##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_git_remote_code_exec_vuln_win.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# Git Remote Code Execution Vulnerability - Windows
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:git_for_windows_project:git_for_windows";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811706");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2017-1000117");
  script_bugtraq_id(100283);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-17 11:01:31 +0530 (Thu, 17 Aug 2017)");
  script_name("Git Remote Code Execution Vulnerability - Windows");

  script_tag(name:"summary", value:"The host is installed with Git
  and is prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error related to the
  handling of 'ssh' URLs.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to execute arbitrary code on the
  affected system.");

  script_tag(name:"affected", value:"Git versions 2.14.x prior to 2.14.1, 2.13.x
  prior to 2.13.5, 2.12.x prior to 2.12.4, 2.11.x prior to 2.11.3, 2.10.x prior to
  2.10.4, 2.9.x prior to 2.9.5, 2.8.x prior to 2.8.6 and 2.7.x prior to 2.7.6.");

  script_tag(name:"solution", value:"Upgrade to Git version 2.14.1 or 2.13.5 or
  2.12.4 or 2.11.3 or 2.10.4 or 2.9.5 or 2.8.6 or 2.7.6 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.esecurityplanet.com/threats/git-svn-and-mercurial-open-source-version-control-systems-update-for-critical-security-vulnerability.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_git_detect_win.nasl");
  script_mandatory_keys("Git/Win/Ver");
  script_xref(name:"URL", value:"https://git-scm.com/download/win");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!git_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(git_ver =~ "^(2\.14\.)" && version_is_less(version:git_ver, test_version:"2.14.1")){
  fix = "2.14.1";
}
else if(git_ver =~ "^(2\.13\.)" && version_is_less(version:git_ver, test_version:"2.13.5")){
  fix = "2.13.5";
}
else if(git_ver =~ "^(2\.12\.)" && version_is_less(version:git_ver, test_version:"2.12.4")){
  fix = "2.12.4";
}
else if(git_ver =~ "^(2\.11\.)" && version_is_less(version:git_ver, test_version:"2.11.3")){
  fix = "2.11.3";
}
else if(git_ver =~ "^(2\.10\.)" && version_is_less(version:git_ver, test_version:"2.10.4")){
  fix = "2.10.4";
}
else if(git_ver =~ "^(2\.9\.)" && version_is_less(version:git_ver, test_version:"2.9.5")){
  fix = "2.9.5";
}
else if(git_ver =~ "^(2\.8\.)" && version_is_less(version:git_ver, test_version:"2.8.6")){
  fix = "2.8.6";
}
else if(git_ver =~ "^(2\.7\.)" && version_is_less(version:git_ver, test_version:"2.7.6")){
  fix = "2.7.6";
}

if(fix)
{
  report = report_fixed_ver(installed_version:git_ver, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
