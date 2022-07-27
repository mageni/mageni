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
  script_oid("1.3.6.1.4.1.25623.1.0.815527");
  script_version("2019-08-14T14:30:23+0000");
  script_cve_id("CVE-2019-1200", "CVE-2019-1204");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-08-14 14:30:23 +0000 (Wed, 14 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-14 11:11:45 +0530 (Wed, 14 Aug 2019)");
  script_name("Microsoft Outlook 2010 Service Pack 2 Multiple Vulnerabilities (KB4475573)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4475573");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Vulnerabilities Details:

  - A remote code execution vulnerability exists in Microsoft Outlook
    software when it fails to properly handle objects in memory.

  - An elevation of privilege vulnerability exists when Microsoft Outlook
    initiates processing of incoming messages without sufficient validation
    of the formatting of the messages.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to perform actions in the security context of the current user and to force Outlook
  to load a local or remote message store (over SMB).");

  script_tag(name:"affected", value:"Microsoft Outlook 2013 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4475573/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Outlook/Version");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

outlookVer = get_kb_item("SMB/Office/Outlook/Version");
if(!outlookVer|| outlookVer !~ "^14\."){
  exit(0);
}

outlookFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE", item:"Path");
if(!outlookFile){
  exit(0);
}

outlookVer = fetch_file_version(sysPath:outlookFile, file_name:"outlook.exe");
if(!outlookVer){
  exit(0);
}

if(version_in_range(version:outlookVer, test_version:"14.0", test_version2:"14.0.7236.4999")){
  report = report_fixed_ver(file_checked: outlookFile + "outlook.exe",
                            file_version:outlookVer, vulnerable_range:"14.0 - 14.0.7236.4999");
  security_message(data:report);
  exit(0);
}
exit(99);
