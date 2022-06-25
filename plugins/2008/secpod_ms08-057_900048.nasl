##############################################################################
# OpenVAS Vulnerability Test
# Description: Microsoft Excel Remote Code Execution Vulnerability (956416)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900048");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-10-15 19:56:48 +0200 (Wed, 15 Oct 2008)");
  script_bugtraq_id(31702, 31705, 31706);
  script_cve_id("CVE-2008-3471", "CVE-2008-3477", "CVE-2008-4019");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Microsoft Excel Remote Code Execution Vulnerability (956416)");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-057.mspx");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Excel/Version");

  script_tag(name:"impact", value:"Remote attackers could corrupt memory via a specially
  crafted Excel (.xls) files.");

  script_tag(name:"affected", value:"Microsoft Execel 2002/XP/2003/2007 on Windows (All).

  Microsoft Execel Viewer 2003/2007 on Windows (All).");

  script_tag(name:"insight", value:"The flaws are due to

  - insufficient validation of data in a VBA Performance Cache.

  - an error in the loading of Excel objects, which in corrupt memory via
    a specially crafted file.

  - an integer overflow in the REPT function when handling formulas inside
    cells.");

  script_tag(name:"summary", value:"This host is missing critical security update according to
  Microsoft Bulletin MS08-057.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

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

  if(version_in_range(version:excelVer, test_version:"9.0", test_version2:"9.0.0.8971")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  else if(version_in_range(version:excelVer, test_version:"10.0", test_version2:"10.0.6846")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  else if(version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8230")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  else if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6324.5000")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
