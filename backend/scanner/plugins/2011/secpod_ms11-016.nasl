###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Groove Remote Code Execution Vulnerability (2494047)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902351");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-03-09 15:35:07 +0100 (Wed, 09 Mar 2011)");
  script_cve_id("CVE-2010-3146");
  script_bugtraq_id(42695);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Groove Remote Code Execution Vulnerability (2494047)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41104/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2188");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS11-016.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Groove/Version", "SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary
  code by tricking a user into opening a file *.vcg from a network share.");
  script_tag(name:"affected", value:"Microsoft Groove 2007 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The application insecurely loading certain libraries (e.g. 'mso.dll') from
  the current working directory.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-016.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");

# MS11-016 Hotfix
if((hotfix_missing(name:"2494047") == 0)){
  exit(0);
}

## Microsoft Groove 2007
exeVer = get_kb_item("SMB/Office/Groove/Version");
if(exeVer =~ "^12\..*")
{
  if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6550.5003"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
