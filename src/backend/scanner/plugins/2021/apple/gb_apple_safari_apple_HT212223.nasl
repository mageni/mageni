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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817974");
  script_version("2021-03-16T11:34:24+0000");
  script_cve_id("CVE-2021-1844");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-17 11:26:15 +0000 (Wed, 17 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-12 15:19:26 +0530 (Fri, 12 Mar 2021)");
  script_name("Apple Safari Security Update (HT212223)");

  script_tag(name:"summary", value:"This host is installed with Apple Safari
  and is prone to a memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a memory corruption issue
  related to an improper input validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution.");

  script_tag(name:"affected", value:"Apple Safari versions before 14.0.3 build
  14610.4.3.1.7 on macOS Mojave and 14.0.3 build 15610.4.3.1.7 on macOS Catalina.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 14.0.3 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT212223");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version", "ssh/login/osx_version");
  exit(0);
}


include("version_func.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[45]\." || "Mac OS X" >!< osName){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
safVer = infos['version'];
safPath = infos['location'];

buildVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                 "Safari.app/Contents/Info CFBundleVersion"));

if(osVer =~ "^10\.15")
{
  if(version_is_less(version:safVer, test_version:"14.0.3")){
    fix = "Upgrade to 14.0.3 and install update";
  }

  else if(safVer == "14.0.3")
  {
    if(version_is_less(version:buildVer, test_version:"15610.4.3.1.7"))
    {
      fix = "Apply update from vendor";
      safVer = safVer + " Build " + buildVer;
    }
  }
}

if(osVer =~ "^10\.14")
{
if(version_is_less(version:safVer, test_version:"14.0.3")){
    fix = "Upgrade to 14.0.3 and install update";
  }

  else if(safVer == "14.0.3")
  {
    if(version_is_less(version:buildVer, test_version:"14610.4.3.1.7"))
    {
      fix = "Apply update from vendor";
      safVer = safVer + " Build " + buildVer;
    }
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:safVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
exit(99);
