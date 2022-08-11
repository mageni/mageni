###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Visual Basic Remote Code Execution Vulnerability (978213)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
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
  script_oid("1.3.6.1.4.1.25623.1.0.902178");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_cve_id("CVE-2010-0815");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Visual Basic Remote Code Execution Vulnerability (978213)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/976380");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/976382");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/976321");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/974945");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1121");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS10-031.mspx");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to crash an affected
  application or execute arbitrary code by tricking a user into opening a specially crafted document.");

  script_tag(name:"affected", value:"Microsoft Office XP SP3 and prior.

  Microsoft Office 2003 SP3 and prior.

  Microsoft Visual Basic for Applications.

  2007 Microsoft Office System SP2 and prior.

  Microsoft Visual Basic for Applications SDK.");

  script_tag(name:"insight", value:"The issue is caused by a stack memory corruption error in 'VBE6.DLL' when
  searching for ActiveX controls in a document that supports VBA.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-031.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, win2k:5) <= 0){
  exit(0);
}

key = registry_key_exists(key:"SOFTWARE\Microsoft\Shared Tools\AddIn Designer\Visual Basic for Applications IDE");

officeVer = get_kb_item("MS/Office/Ver");

if(isnull(key)){
  if(isnull(officeVer)){
    exit(0);
  }
}

if((officeVer =~ "^1[012]\..*") || !isnull(key))
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
  if(!dllPath){
    exit(0);
  }

  dllPath = dllPath + "\Common Files\Microsoft Shared\VBA\VBA6\VBE6.DLL";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

  dllVer = GetVer(file:file, share:share);
  if(!dllVer){
    exit(0);
  }

  if(version_is_less(version:dllVer, test_version:"6.5.10.53")){
    report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.5.10.53", file_checked:dllPath);
    security_message(port:0, data:report );
  }
}

exit(0);