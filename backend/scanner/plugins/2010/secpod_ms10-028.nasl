###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Visio Remote Code Execution Vulnerabilities (980094)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902039");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-04-14 17:51:53 +0200 (Wed, 14 Apr 2010)");
  script_cve_id("CVE-2010-0254", "CVE-2010-0256");
  script_bugtraq_id(39300, 39302);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Visio Remote Code Execution Vulnerabilities (980094)");
  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-09-005");
  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-09-006");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Apr/1023856.html");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS10-028.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow users to execute arbitrary code via a
  specially crafted Visio file.");
  script_tag(name:"affected", value:"Microsoft Office Visio 2002/2003/2007 on Windows");
  script_tag(name:"insight", value:"The flaws exist due to the way that Microsoft Office Visio calculates
  'indexes' and validates 'attributes' when handling specially crafted Visio
  files.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-028.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

ovPath = registry_get_sz(item:"Path",
         key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\visio.exe");

if(!ovPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ovPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:ovPath + "visio.exe");

exeVer = GetVer(file:file, share:share);
if(!exeVer){
  exit(0);
}

if(version_in_range(version:exeVer, test_version:"11.0", test_version2:"11.0.8206" ) ||
   version_in_range(version:exeVer, test_version:"10.0", test_version2:"10.0.6890.3") ||
   version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6520.4999")){
 security_message( port: 0, data: "The target host was found to be vulnerable" );
}
