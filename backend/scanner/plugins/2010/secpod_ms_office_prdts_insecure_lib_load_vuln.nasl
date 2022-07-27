###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Products Insecure Library Loading Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2015 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902254");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2010-3141", "CVE-2010-3142", "CVE-2010-3146", "CVE-2010-3148");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-09-09 10:16:10 +0530 (Wed, 09 Sep 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Office Products Insecure Library Loading Vulnerability");

  script_tag(name:"summary", value:"This host is installed with microsoft
  product(s) and is prone to insecure library loading vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the application
  insecurely loading certain libraries from the current working directory,
  which could allow attackers to execute arbitrary code by tricking a user into
  opening a file from a network share.");

  script_tag(name:"impact", value:"Successful exploitation will allow the
  attackers to execute arbitrary code and conduct DLL hijacking attacks.");

  script_tag(name:"affected", value:"Microsoft Visio 2003,

  Microsoft Office Groove 2007,

  Microsoft Office PowerPoint 2007/2010");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14723/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14782/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14746/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14744/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2188");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2192");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SecPod");
  script_family("Windows");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver", "MS/Office/Prdts/Installed");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-055");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer){
  exit(0);
}

ver = get_kb_item("SMB/Office/PowerPnt/Version");
if(ver && (ver =~ "^(12|14)\..*"))
{
  if(version_in_range(version:ver, test_version:"14.0", test_version2:"14.0.4760.1000") ||
     version_in_range(version:ver, test_version:"12.0", test_version2:"12.0.6535.5002"))
  {
    VULN = TRUE ;
    fix = "Apply the patch";
  }
}

else if(ver = get_kb_item("SMB/Office/Groove/Version"))
{
  if(ver && (ver =~ "^12\..*"))
  {
    if(version_is_less(version:ver, test_version:"12.0.6550.5004"))
    {
      VULN = TRUE ;
      fix = "12.0.6550.5004";
    }
  }
}

if(VULN)
{
  report = 'Installed version: ' + ver + '\n' +
           'Fixed version: '  +  fix + '\n';
  security_message(data:report);
  exit(0);
}

if(ovPath = registry_get_sz(item:"Path",
         key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\visio.exe"))
{
  offPath = ovPath  - "\Visio11" + "OFFICE11";
  ver = fetch_file_version(sysPath:offPath, file_name:"Omfc.dll");
  if(ver && (ver =~ "^11\..*"))
  {
    if(version_is_less(version:ver, test_version:"11.0.8332.0"))
    {
      VULN = TRUE ;
      fix = "11.0.8332.0";
    }
  }
}

if(VULN)
{
  report = 'Installed version: ' + ver + '\n' +
           'Fixed version: '  +  fix + '\n';
  security_message(data:report);
  exit(0);
}
