###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Products '.pdf' and '.swf' Code Execution Vulnerability - July09 (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900806");
  script_version("2019-05-24T11:20:30+0000");
  script_cve_id("CVE-2009-1862");
  script_bugtraq_id(35759);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_name("Adobe Products '.pdf' and '.swf' Code Execution Vulnerability - July09 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe products and are prone to remote code
  execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- An unspecified error exists in Adobe Flash Player which can be exploited via
  a specially crafted flash application in a '.pdf' file.

  - Error occurs in 'authplay.dll' in Adobe Reader/Acrobat while processing '.swf'
  content and can be exploited to execute arbitrary code.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause code execution.");

  script_tag(name:"affected", value:"Adobe Reader/Acrobat version 9.x to 9.1.2

  Adobe Flash Player version 9.x to 9.0.159.0 and 10.x to 10.0.22.87 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader/Acrobat version 9.1.3 or later.

  Upgrade to Adobe Flash Player version 9.0.246.0 or 10.0.32.18 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35948/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35949/");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/259425");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa09-03.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl", "secpod_adobe_prdts_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:flash_player";
if(playerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_in_range(version:playerVer, test_version:"9.0", test_version2:"9.0.159.0") ||
     version_in_range(version:playerVer, test_version:"10.0", test_version2:"10.0.22.87"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  authplayDll = registry_get_sz(key:"SOFTWARE\Adobe\Acrobat Reader\9.0" +
                                    "\Installer", item:"Path");
  if(!authplayDll){
    break;
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:authplayDll);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:authplayDll + "\Reader\authplay.dll");
  fileVer = GetVer(file:file, share:share);

  if(fileVer =~ "9.0")
  {
    if(version_in_range(version:readerVer, test_version:"9.0",
                                           test_version2:"9.1.2")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE))
{
  authplayDll = registry_get_sz(key:"SOFTWARE\Adobe\Adobe Acrobat\9.0" +
                                    "\Installer", item:"Path");
  if(!authplayDll){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:authplayDll);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:authplayDll + "\Acrobat\authplay.dll");

  fileVer = GetVer(file:file, share:share);
  if(fileVer =~ "9.0")
  {
    if(version_in_range(version:acrobatVer, test_version:"9.0",
                                            test_version2:"9.1.2"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}
