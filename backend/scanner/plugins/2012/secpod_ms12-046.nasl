###############################################################################
# OpenVAS Vulnerability Test
#
# Visual Basic for Applications Remote Code Execution Vulnerability (2707960)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903034");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-1854");
  script_bugtraq_id(54303);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-07-11 12:07:45 +0530 (Wed, 11 Jul 2012)");
  script_name("Visual Basic for Applications Remote Code Execution Vulnerability (2707960)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code affected system.");
  script_tag(name:"affected", value:"Microsoft Visual Basic for Applications,
  Microsoft Office 2003 Service Pack 3 and prior,
  Microsoft Office 2007 Service Pack 3 and prior,
  Microsoft Office 2010 Service Pack 1 and prior.");
  script_tag(name:"insight", value:"Microsoft Visual Basic for Applications incorrectly restricts the path used
  for loading external libraries, which can be exploited by tricking a user to
  open a legitimate Microsoft Office related file located in the same network
  directory as a specially crafted dynamic link library (DLL) file.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-046.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49800/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/976321");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2598243");
  script_xref(name:"URL", value:"http://support.microsoft.com/KB/2598361");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553447");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2688865");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/KB2598361");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-046");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
              item:"CommonFilesDir");
if(!dllPath){
  exit(0);
}

officeVer = get_kb_item("MS/Office/Ver");

dllVer6 = fetch_file_version(sysPath:dllPath,
              file_name:"Microsoft Shared\VBA\VBA6\VBE6.DLL");

if(dllVer6)
{
  if(version_is_less(version:dllVer6, test_version:"6.5.10.54"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

if(officeVer =~ "^14\..*")
{
  dllVer7 = fetch_file_version(sysPath:dllPath,
           file_name:"Microsoft Shared\VBA\VBA7\VBE7.DLL");

  if(dllVer7)
  {
    if(version_in_range(version:dllVer7, test_version:"7.0", test_version2:"7.0.16.26"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  accVer = fetch_file_version(sysPath:dllPath,
             file_name:"Microsoft Shared\OFFICE14\ACEES.DLL");

  if(accVer)
  {
    if(version_in_range(version:accVer, test_version:"14.0", test_version2:"14.0.6015.999")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
