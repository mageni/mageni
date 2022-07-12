###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (2293386)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900261");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-11-10 14:58:25 +0100 (Wed, 10 Nov 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2572", "CVE-2010-2573");
  script_bugtraq_id(44626, 44628);
  script_name("Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (2293386)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2413272");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2413304");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2413381");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms10-088.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "MS/Office/Prdts/Installed");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a malicious PPT file.");

  script_tag(name:"affected", value:"Microsoft PowerPoint 2002 Service Pack 3 and prior

  Microsoft PowerPoint 2003 Service Pack 3 and prior

  Microsoft PowerPoint Viewer 2007 Service Pack 2 and prior");

  script_tag(name:"insight", value:"The flaw is due to the way that Microsoft PowerPoint parses the
  PPT file format when opening a specially crafted files.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-088.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

if(officeVer && officeVer =~ "^1[0-2]\.")
{
  pptVer = get_kb_item("SMB/Office/PowerPnt/Version");
  ppviewVer = get_kb_item("SMB/Office/PPView/Version");

  if(pptVer && pptVer =~ "^1[01]\.")
  {
    if(version_in_range(version:pptVer, test_version:"10.0", test_version2:"10.0.6857") ||
       version_in_range(version:pptVer, test_version:"11.0", test_version2:"11.0.8323")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }

  if(ppviewVer && ppviewVer =~ "^12\.")
  {
    if(version_in_range(version:ppviewVer, test_version:"12.0", test_version2:"12.0.6545.5003")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
