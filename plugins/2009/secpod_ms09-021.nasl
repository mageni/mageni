###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Excel Remote Code Execution Vulnerabilities (969462)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
# Sharath S <ssharath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900670");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-06-12 17:18:17 +0200 (Fri, 12 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0549", "CVE-2009-0557", "CVE-2009-0558", "CVE-2009-0559",
                "CVE-2009-0560", "CVE-2009-0561", "CVE-2009-1134");
  script_bugtraq_id(35215, 35241, 35242, 35243, 35244, 35245, 35246);
  script_name("Microsoft Office Excel Remote Code Execution Vulnerabilities (969462)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver", "MS/Office/Prdts/Installed");

  script_tag(name:"impact", value:"Successful exploitation could execute arbitrary code on the remote system
  and corrupt memory, buffer overflow via a specially crafted Excel file.");

  script_tag(name:"affected", value:"Microsoft Excel Viewer 2003/2007

  Microsoft Office Excel 2000/2002/2003/2007");

  script_tag(name:"insight", value:"The flaws are due to

  - an array-indexing error when processing certain records by using corrupted
    object.

  - a boundary error when parsing certain records by opening a specially
    crafted Excel file.

  - an integer overflow error when processing the number of strings in a file.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-021.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35364");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/969462");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms09-021.mspx");

  exit(0);
}

include("version_func.inc");

officeVer = get_kb_item("MS/Office/Ver");
excelVer = get_kb_item("SMB/Office/Excel/Version");

if(officeVer && officeVer =~ "^(9|1[0-2])\.")
{
  if(excelVer)
  {
    if(version_in_range(version:excelVer, test_version:"9.0", test_version2:"9.0.0.8978")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    else if(version_in_range(version:excelVer, test_version:"10.0", test_version2:"10.0.6853.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    else if(version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8306.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    else if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6504.5000")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

if(excelVer =~ "^1[12]\." )
{
  xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");
  if(xlcnvVer)
  {
    if(version_in_range(version:xlcnvVer, test_version:"12.0", test_version2:"12.0.6504.5000"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

# For Microsoft Office Excel Viewer 2003/2007
xlviewVer = get_kb_item("SMB/Office/XLView/Version");
if(xlviewVer)
{
 # Office Excel Viewer 2007 version 12.0 < 12.0.6504.5000
 if(version_in_range(version:xlviewVer, test_version:"11.0", test_version2:"11.0.8306.0") ||
    version_in_range(version:xlviewVer, test_version:"12.0", test_version2:"12.0.6504.4999")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
