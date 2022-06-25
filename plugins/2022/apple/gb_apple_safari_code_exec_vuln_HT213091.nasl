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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.820003");
  script_version("2022-02-22T06:48:08+0000");
  script_cve_id("CVE-2022-22620");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-22 11:21:00 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-15 11:15:38 +0530 (Tue, 15 Feb 2022)");
  script_name("Apple Safari Code Execution Vulnerability (HT213091)");

  script_tag(name:"summary", value:"Apple Safari is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an use after free issue
  related to improper memory management.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  conduct arbitrary code execution.");

  script_tag(name:"affected", value:"Apple Safari versions before 15.3 build 16612.4.9.1.8 on
  macOS Big Sure and 15.3 build 15612.4.9.1.8 on macOS Catalina.");

  script_tag(name:"solution", value:"Update to Apple Safari 15.3 build 16612.4.9.1.8
  on macOS Big Sure and 15.3 build 15612.4.9.1.8 on macOS Catalina. Please see the
  references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213091");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version", "ssh/login/osx_version");
  exit(0);
}
include("version_func.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || (osVer !~ "^10\.15\." && osVer !~ "^11\.") || "Mac OS X" >!< osName)
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

buildVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Safari.app/Contents/Info CFBundleVersion"));

if(osVer =~ "^10\.15") {
  if(version_is_less(version:vers, test_version:"15.3"))
    fix = "Upgrade to 15.3 and install update";

  else if(vers == "15.3") {
    if(version_is_less(version:buildVer, test_version:"15612.4.9.1.8")) {
      fix = "Apply update from vendor";
      vers = vers + " Build " + buildVer;
    }
  }
}

if(osVer =~ "^11\.") {
  if(version_is_less(version:vers, test_version:"15.3"))
    fix = "Upgrade to 15.3 and install update";

  else if(vers == "15.3") {
    if(version_is_less(version:buildVer, test_version:"16612.4.9.1.8")) {
      fix = "Apply update from vendor";
      vers = vers + " Build " + buildVer;
    }
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
