# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.826922");
  script_version("2023-02-21T10:09:30+0000");
  script_cve_id("CVE-2023-23529");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-02-21 10:09:30 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-16 12:12:21 +0530 (Thu, 16 Feb 2023)");
  script_name("Apple Safari Code Execution Vulnerability (HT213638)");

  script_tag(name:"summary", value:"Apple Safari is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a type confusion issue
  due to improper checks.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  conduct arbitrary code execution.");

  script_tag(name:"affected", value:"Apple Safari versions before 16.3 build
  167614.4.6.11.6 on macOS Big Sur and 16.3 build 177614.4.6.11.6 on macOS Monterey.");

  script_tag(name:"solution", value:"Update Apple Safari to 16.3 build 167614.4.6.11.6
  on macOS Big Sur and 16.3 build 177614.4.6.11.6 on macOS Monterey. Please see the
  references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213638");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
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
if(!osVer || (osVer !~ "^12\." && osVer !~ "^11\.") || "Mac OS X" >!< osName)
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

buildVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Safari.app/Contents/Info CFBundleVersion"));

if(osVer =~ "^11\.") {
  if(version_is_less(version:vers, test_version:"16.3"))
    fix = "Upgrade to 16.3 and install update";

  else if(vers == "16.3") {
    if(version_is_less(version:buildVer, test_version:"167614.4.6.11.6")) {
      fix = "Apply update from vendor";
      vers = vers + " Build " + buildVer;
    }
  }
}

if(osVer =~ "^12\.") {
  if(version_is_less(version:vers, test_version:"16.3"))
    fix = "Upgrade to 16.3 and install update";

  else if(vers == "16.3") {
    if(version_is_less(version:buildVer, test_version:"177614.4.6.11.6")) {
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
