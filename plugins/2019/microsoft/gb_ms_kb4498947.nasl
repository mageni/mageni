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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815133");
  script_version("2019-05-16T13:15:53+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-16 13:15:53 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-16 11:38:35 +0530 (Thu, 16 May 2019)");
  script_name("Microsoft Windows Latest Servicing Stack Updates-Defense in Depth (KB4498947)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4498947.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Microsoft has released latest servicing stack
  updates that provides enhanced security as a defense in depth measure.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attackers
  to bypass a security control or take advantage of a vulnerability.");

  script_tag(name:"affected", value:"Windows 10 Version 1607 32-bit Systems

  Windows 10 Version 1607 for x64-based Systems

  Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4498947/windows-10-update-kb4498947");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV990001");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "WMI/access_successful");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("misc_func.inc");
include("wmi_file.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0)
  exit(0);

sysPath = smb_get_system32root();
if(!sysPath)
  exit(0);

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer)
  exit(0);

if(edgeVer =~ "11\.0\.14393")
{
  infos = kb_smb_wmi_connectinfo();
  if(!infos)
    exit(0);

  handle = wmi_connect(host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"]);
  if(!handle)
    exit(0);

  fileList = wmi_file_fileversion(handle:handle, fileName:"smiengine", fileExtn:"dll", includeHeader:FALSE);
  wmi_close(wmi_handle:handle);
  if(!fileList || !is_array(fileList))
    exit(0);

  max_version = 0; # Avoid passing null to the version function below
  foreach filePath(keys(fileList)) {
    vers = fileList[filePath];
    if(vers =~ "^10\.0" && version = eregmatch(string:vers, pattern:"^([0-9.]+)")) {
      if(version_is_less_equal(version:version[1], test_version:max_version)) {
        continue;
      } else {
        max_version = version[1];
        path = filePath;
      }
    }
  }

  if(max_version && version_is_less(version:max_version, test_version:"10.0.14393.2963")) {
    report = report_fixed_ver(file_checked:path, file_version:max_version, vulnerable_range:"Less than 10.0.10240.17831");
    security_message(data:report);
    exit(0);
  }
}
exit(99);
