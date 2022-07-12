###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Excel Remote Code Execution Vulnerabilities (968557)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Update description and file check to reflect MS09-009 Bulletin.
#  - By Chandan S, 2009-04-15 14:47:49
#
# Make use of version_func_inc - By Chandan S, 11:48:13 2009/04/24
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900476");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-03-18 14:42:27 +0100 (Wed, 18 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0238", "CVE-2009-0100");
  script_bugtraq_id(33870, 34413);
  script_name("Microsoft Excel Remote Code Execution Vulnerabilities (968557)");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms09-009.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Excel/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary code by tricking
  a user into opening a specially crafted Excel file.");

  script_tag(name:"affected", value:"Microsoft Office Excel 2K  SP3

  Microsoft Office Excel 2k2 SP3

  Microsoft Office Excel 2k3 SP3

  Microsoft Office Excel 2k7 SP1");

  script_tag(name:"insight", value:"Flaws are due to Memory corruption error and an invalid object access when
  processing a malformed Excel document, which in cause a application crash.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-009.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

if(officeVer && officeVer =~ "^(9|1[0-2])\.")
{
  excelVer = get_kb_item("SMB/Office/Excel/Version");
  if(!excelVer || excelVer !~ "^(9|1[0-2])\."){
    exit(0);
  }

  if(version_in_range(version:excelVer, test_version:"9.0", test_version2:"9.0.0.8976")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  else if(version_in_range(version:excelVer, test_version:"10.0", test_version2:"10.0.6851")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  else if(version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8301")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  else if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6341.5000")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
