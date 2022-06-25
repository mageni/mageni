###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Visio Viewer Remote Code Execution Vulnerability (2597981)
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
  script_oid("1.3.6.1.4.1.25623.1.0.902910");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-0018");
  script_bugtraq_id(53328);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-05-09 08:45:22 +0530 (Wed, 09 May 2012)");
  script_name("Microsoft Office Visio Viewer Remote Code Execution Vulnerability (2597981)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49113");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2597981");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/49113");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS12-031");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/VisioViewer/Ver");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to gain same user rights as
  the logged on user and execute arbitrary code.");
  script_tag(name:"affected", value:"Microsoft Visio Viewer 2010 Service Pack 1 and prior");
  script_tag(name:"insight", value:"The flaw is due to an error when validating certain attributes within
  a 'VSD' file format and can be exploited to corrupt memory via a specially
  crafted Visio file.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-031.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-031");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

vvVer = get_kb_item("SMB/Office/VisioViewer/Ver");
if(vvVer && vvVer =~ "^14\..*")
{
  visioPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                              item:"ProgramFilesDir");
  if(visioPath)
  {
    dllPath = visioPath + "\Microsoft Office\Office14\";
    if(dllPath)
    {
      visiovVer = fetch_file_version(sysPath:dllPath, file_name:"VVIEWER.dll");
      if(visiovVer)
      {
        if(version_in_range(version:visiovVer, test_version:"14.0", test_version2:"14.0.6117.5002")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
    }
  }
}
