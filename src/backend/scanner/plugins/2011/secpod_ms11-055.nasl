###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Visio Remote Code Execution Vulnerability (2560847)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902455");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2010-3148");
  script_bugtraq_id(42681);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_name("Microsoft Visio Remote Code Execution Vulnerability (2560847)");

  script_tag(name:"summary", value:"This host is missing an important
  security update according to Microsoft Bulletin MS11-055.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the way that Microsoft
  Office Visio loads external libraries, when handling specially crafted Visio files.");

  script_tag(name:"impact", value:"Successful exploitation could allow
  users to execute arbitrary code via a specially crafted visio file.");

  script_tag(name:"affected", value:"Microsoft Office Visio 2003 SP3 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2493523");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS11-055.mspx");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS11-055.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


ovPath = registry_get_sz(item:"Path",
         key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\visio.exe");

if(!ovPath){
  exit(0);
}

offPath = ovPath  - "\Visio11" + "OFFICE11";
dllVer = fetch_file_version(sysPath:offPath, file_name:"Omfc.dll");
if(!dllVer){
  exit(0);
}

if(version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.8331.0")){
   report = 'File checked:     ' + offPath + "Omfc.dll" + '\n' +
            'File version:     ' + dllVer  + '\n' +
            'Vulnerable range: 11.0 - 11.0.8331.0 \n' ;
   security_message(data:report);
   exit(0);
}
