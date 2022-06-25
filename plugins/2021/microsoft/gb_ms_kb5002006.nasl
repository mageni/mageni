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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818906");
  script_version("2021-10-14T03:43:45+0000");
  script_cve_id("CVE-2021-40486");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-14 10:10:07 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-13 12:01:31 +0530 (Wed, 13 Oct 2021)");
  script_name("Microsoft SharePoint Enterprise Server 2016 RCE Vulnerability (KB5002006)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5002006");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the presence of an
  error when a maliciously modified file is opened in Microsoft SharePoint Server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Microsoft SharePoint Enterprise Server 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002006");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


if(!infos = get_app_version_and_location(cpe:"cpe:/a:microsoft:sharepoint_server", exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
if(!vers || vers !~ "^16\.")
  exit(0);

if(!os_arch = get_kb_item("SMB/Windows/Arch"))
  exit(0);

if("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion");
}

else if("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion",
                       "SOFTWARE\Microsoft\Windows\CurrentVersion");
}

foreach key(key_list) {
  path = registry_get_sz(key:key, item:"CommonFilesDir");
  if(path) {
    path = path + "\microsoft shared\SERVER16\Server Setup Controller";
    dllVer = fetch_file_version(sysPath:path, file_name:"wsssetup.dll");
    if(dllVer =~ "^16\." && version_is_less(version:dllVer, test_version:"16.0.5227.1000")) {
      report = report_fixed_ver(file_checked:path + "\wsssetup.dll",
                                file_version:dllVer, vulnerable_range:"16.0 - 16.0.5227.0999");
      security_message(data:report);
      exit(0);
    }
  }
}
exit(99);
