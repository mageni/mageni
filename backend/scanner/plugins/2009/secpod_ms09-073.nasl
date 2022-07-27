###############################################################################
# OpenVAS Vulnerability Test
#
# WordPad and Office Text Converters Remote Code Execution Vulnerability (975539)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-03-23
#  - Included the file version check for 'Msconv97.dll'
#  - Removed dead code
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901068");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-12-09 16:08:24 +0100 (Wed, 09 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2506");
  script_name("WordPad and Office Text Converters Remote Code Execution Vulnerability (975539)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/973904");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/975008");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/974882");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/977304");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3438");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS09-073.mspx");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to crash an affected
  application or execute arbitrary code by tricking a user into opening a specially crafted document.");

  script_tag(name:"affected", value:"Microsoft Works 8.5

  Microsoft Office Converter Pack

  Microsoft Office XP Service Pack 3

  Microsoft Office 2003 Service Pack 3

  Microsoft Office Word 2002 Service Pack 3

  Microsoft Office Word 2003 Service Pack 3

  Microsoft Windows XP  Service Pack 3 and prior

  Microsoft Windows 2K3 Service Pack 2 and prior

  Microsoft Windows 2000  Service Pack 4 and prior");

  script_tag(name:"insight", value:"The issue is caused by a memory corruption error in the way that the text
  converter for Word 97 (included as part of WordPad and as part of the Office
  text converters) parses a specially crafted Word 97 document.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-073.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms09-073.mspx");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, win2k:5) <= 0){
  exit(0);
}

# MS09-073 Hotfix check
if(hotfix_missing(name:"973904") == 0){
  exit(0);
}

dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
if(!dllPath){
  exit(0);
}

dllPath = dllPath + "\Common Files\Microsoft Shared\TextConv\Msconv97.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

if(version_is_less(version:dllVer, test_version:"2003.1100.8165.0")){
  report = report_fixed_ver(installed_version:dllVer, fixed_version:"2003.1100.8165.0", file_checked:dllPath);
  security_message(port:0, data:report );
}

exit(0);