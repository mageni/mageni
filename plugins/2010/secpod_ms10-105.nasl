###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Graphics Filters Remote Code Execution Vulnerabilities (968095)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801489");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-12-15 14:53:45 +0100 (Wed, 15 Dec 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3945", "CVE-2010-3946", "CVE-2010-3947", "CVE-2010-3949",
                "CVE-2010-3950", "CVE-2010-3951", "CVE-2010-3952");
  script_bugtraq_id(45270, 45273, 45274, 45275, 45278, 45283, 45285);
  script_name("Microsoft Office Graphics Filters Remote Code Execution Vulnerabilities (968095)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3227");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms10-105.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  by tricking a user into opening a malicious document file.");

  script_tag(name:"affected", value:"Microsoft Office XP Service Pack 3

  Microsoft Office 2003 Service Pack 3

  Microsoft Office 2007 Service Pack 2

  Microsoft Office Converter Pack

  Microsoft Office 2010.");

  script_tag(name:"insight", value:"Multiple flaws are caused by, buffer and integer overflows and memory
  corruption errors in processing CGM, PICT, TIFF, FlashPix image files.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-105.");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

function FileVer (file, path)
{
  share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:path);
  file = ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:path + file);

  ver = GetVer(file:file, share:share);
  if(!ver){
    return(FALSE);
  }

  return ver;
}

officeVer = get_kb_item("MS/Office/Ver");

## MS Office XP, 2003, Converter Pack
if(officeVer && officeVer =~ "^1[01]\.")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
  filePath = path + "\Microsoft Shared\GRPHFLT";
  fileVer = FileVer(file:"\gifimp32.flt", path:filePath);
  if(fileVer)
  {
    if(version_is_less(version:fileVer, test_version:"2003.1100.8327.0")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
    }
  }
}

## MS Office 2007, 2010
if(officeVer && officeVer =~ "^1[24]\.")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
  filePath = path + "\Microsoft Shared\TextConv";
  fileVer = FileVer(file:"\msconv97.dll", path:filePath);
  if(fileVer)
  {
    if(version_in_range(version:fileVer, test_version:"2006.0", test_version2:"2006.1200.6539.5003") ||
       version_in_range(version:fileVer, test_version:"2010.0", test_version2:"2010.1400.5114.5003")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
    }
  }
}
