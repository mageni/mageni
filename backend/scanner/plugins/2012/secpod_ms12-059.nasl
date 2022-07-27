###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Visio/Viewer Remote Code Execution Vulnerability (2733918)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902921");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-1888");
  script_bugtraq_id(54934);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-08-15 09:48:21 +0530 (Wed, 15 Aug 2012)");
  script_name("Microsoft Office Visio/Viewer Remote Code Execution Vulnerability (2733918)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50228/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2597171");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2598287");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS12-059");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to gain same user rights as
  the logged on user and execute arbitrary code.");
  script_tag(name:"affected", value:"Microsoft Visio 2010 Service Pack 1 and prior
  Microsoft Visio Viewer 2010 Service Pack 1 and prior");
  script_tag(name:"insight", value:"Error in the way that Microsoft Office Visio/Viewer validates data when
  parsing specially crafted Visio files and can be exploited to corrupt memory
  via a specially crafted Visio file.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-059.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-059");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                             "\App Paths\visio.exe", item:"Path");
if(sysPath)
{
  exeVer = fetch_file_version(sysPath:sysPath, file_name:"visio.exe");
  if(exeVer)
  {
    if(version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.6122.4999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

vvVer = get_kb_item("SMB/Office/VisioViewer/Ver");
if(vvVer && vvVer =~ "^14\..*")
{
  if(version_in_range(version:vvVer, test_version:"14.0", test_version2:"14.0.6116.4999")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
