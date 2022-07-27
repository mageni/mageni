###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Outlook 2007 Service Pack 3 Defense in Depth Vulnerability (KB4011086)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811764");
  script_version("2019-05-20T11:12:48+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-14 14:48:51 +0530 (Thu, 14 Sep 2017)");
  script_name("Microsoft Outlook 2007 Service Pack 3 Defense in Depth Vulnerability (KB4011086)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4011086");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Microsoft has released an update for
  Microsoft Office that provides enhanced security as a defense-in-depth
  measure.");

  script_tag(name:"impact", value:"Microsoft has released an update for
  Microsoft Office that provides enhanced security as a defense-in-depth
  measure.");

  script_tag(name:"affected", value:"Microsoft Outlook 2007 Service Pack 3");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4011086");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/Office/Outlook/Version");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

outlookVer = get_kb_item("SMB/Office/Outlook/Version");

if(!outlookVer || outlookVer !~ "^12\."){
  exit(0);
}

outlookFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\App Paths\OUTLOOK.EXE", item:"Path");
if(!outlookFile){
  exit(0);
}

##Path for Outllibr.dll: 1110,1033; From KB here 1033
path = outlookFile + "1033";
outlookVer = fetch_file_version(sysPath:path, file_name:"Outllibr.dll");
if(!outlookVer){
  exit(0);
}

if(version_in_range(version:outlookVer, test_version:"12.0", test_version2:"12.0.6773.4999"))
{
  report = 'File checked:     ' +  path + "\outlook.exe" + '\n' +
           'File version:     ' +  outlookVer  + '\n' +
           'Vulnerable range:  12.0 - 12.0.6773.4999'+ '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
