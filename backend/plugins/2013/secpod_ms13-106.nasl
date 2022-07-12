###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Shared Component Security Bypass Vulnerability (2905238)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903420");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2013-5057");
  script_bugtraq_id(64095);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-12-11 11:33:55 +0530 (Wed, 11 Dec 2013)");
  script_name("Microsoft Office Shared Component Security Bypass Vulnerability (2905238)");


  script_tag(name:"summary", value:"This host is missing an important security update according to
Microsoft Bulletin MS13-106.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"insight", value:"A Microsoft Office shared component does not properly implement Address
Space Layout Randomization (ASLR).");
  script_tag(name:"affected", value:"Microsoft Office 2007 Service Pack 3 and prior
Microsoft Office 2010 Service Pack 2 and prior");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass the ASLR
security feature and disclose certain sensitive information.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2850022");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2850016");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1029465");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-106");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

offVer = get_kb_item("MS/Office/Ver");
if(!offVer){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(!path){
  exit(0);
}


## Microsoft Office 2007, 2010
if(offVer =~ "^(12|14)\..*")
{
  filePath = path + "\Microsoft Shared\Help";

  fileVer = fetch_file_version(sysPath:filePath, file_name:"hxds.dll");
  if(fileVer)
  {
    ## Microsoft Office 2007
    ## Microsoft Office 2010
    if(version_is_less(version:fileVer, test_version:"5.70.51021"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}
