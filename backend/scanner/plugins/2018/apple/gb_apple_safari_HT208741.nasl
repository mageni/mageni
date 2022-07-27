###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Safari Security Updates(HT208741)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813319");
  script_version("2019-05-22T12:34:41+0000");
  script_cve_id("CVE-2018-4200", "CVE-2018-4204");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-22 12:34:41 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2018-04-25 11:47:33 +0530 (Wed, 25 Apr 2018)");
  script_name("Apple Safari Security Updates(HT208741)");

  script_tag(name:"summary", value:"This host is installed with Apple Safari
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A memory corruption issue related to state management.

  - A memory corruption issue related to improper memory handling.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct arbitrary code execution.");

  script_tag(name:"affected", value:"Apple Safari versions before 11.1
  (11605.1.33.1.4) on OS X El Capitan 10.11.6, before 11.1 (12605.1.33.1.4) on macOS
  Sierra 10.12.6 and before 11.1 (13605.1.33.1.4) on macOS High Sierra 10.13.4.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 11.1 (11605.1.33.1.4)
  on OS X El Capitan 10.11.6, 11.1 (12605.1.33.1.4) on macOS Sierra 10.12.6 or
  11.1 (13605.1.33.1.4) on macOS High Sierra 10.13.4 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208741");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl", "gather-package-list.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.1[1-3]\.");

  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE)) exit(0);
safVer = infos['version'];
path = infos['location'];

if(safVer != "11.1"){
  exit(0);
}

sock = ssh_login_or_reuse_connection();
if(!sock) {
  exit(0);
}

if(!osVer = get_kb_item("ssh/login/osx_version")){
  exit(0);
}

if(safVer == "11.1")
{
  ver = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Safari.app/Contents/Info CFBundleVersion"));

  if(osVer =~ "^10\.11" && version_is_less(version:ver, test_version:"11605.1.33.1.4")){
    fix = "11.1 (11605.1.33.1.4)";
  }
  else if(osVer =~ "^10\.12" && version_is_less(version:ver, test_version:"12605.1.33.1.4")){
    fix = "11.1 (12605.1.33.1.4)";
  }
  else if(osVer =~ "^10\.13" && version_is_less(version:ver, test_version:"13605.1.33.1.4")){
    fix = "11.1 (13605.1.33.1.4)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:safVer + " (" + ver + ")", fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);