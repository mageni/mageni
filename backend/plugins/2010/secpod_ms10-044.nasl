###############################################################################
# OpenVAS Vulnerability Test
#
# MS Office Access ActiveX Controls Remote Code Execution Vulnerabilities(982335)
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
  script_oid("1.3.6.1.4.1.25623.1.0.902218");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-07-14 10:07:03 +0200 (Wed, 14 Jul 2010)");
  script_cve_id("CVE-2010-0814", "CVE-2010-1881");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("MS Office Access ActiveX Controls Remote Code Execution Vulnerabilities(982335)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1799");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms10-044.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Access/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to compromise a
  vulnerable system by tricking a user into visiting a specially crafted
  web page.");
  script_tag(name:"affected", value:"Microsoft Office Access 2003/2007");
  script_tag(name:"insight", value:"The flaws are caused by a memory corruption and an uninitialized variable
  within 'ACCWIZ.dll' (Microsoft Access Wizard Controls) ActiveX control.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-044.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

accVer = get_kb_item("SMB/Office/Access/Version");
if(!accVer){
  exit(0);
}

if(version_in_range(version:accVer, test_version:"11.0", test_version2:"11.0.8320") ||
   version_in_range(version:accVer, test_version:"12.0", test_version2:"12.0.6535.5004")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
