###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Excel Remote Code Execution Vulnerability (2269707)
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
  script_oid("1.3.6.1.4.1.25623.1.0.902095");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-08-11 15:08:29 +0200 (Wed, 11 Aug 2010)");
  script_cve_id("CVE-2010-2562");
  script_bugtraq_id(42199);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Office Excel Remote Code Execution Vulnerability (2269707)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2054");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms10-057.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Excel/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code or to
  compromise a vulnerable system.");
  script_tag(name:"affected", value:"Microsoft Office Excel 2002 Service Pack 3
  Microsoft Office Excel 2003 Service Pack 3");
  script_tag(name:"insight", value:"The issue is caused by a memory corruption error when processing malformed
  Excel data, which could be exploited by attackers to execute arbitrary code
  by tricking a user into opening a malicious document.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-057.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer =~ "^(10|11)\..*")
{
  if(version_in_range(version:excelVer, test_version:"10.0", test_version2:"10.0.6863") ||
     version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8325")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
