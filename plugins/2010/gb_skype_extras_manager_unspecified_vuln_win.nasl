###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_skype_extras_manager_unspecified_vuln_win.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Skype Extras Manager Unspecified Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801302");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2009-4741");
  script_bugtraq_id(36459);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Skype Extras Manager Unspecified Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37012");
  script_xref(name:"URL", value:"https://developer.skype.com/WindowsSkype/ReleaseNotes#head-21c1b2583e7cc405f994ca162d574fb15a6e986b");

  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_skype_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Skype/Win/Ver");
  script_tag(name:"impact", value:"It has unknown impact and attack vectors.");
  script_tag(name:"affected", value:"Skype version prior to 4.1.0.179 on windows.");
  script_tag(name:"insight", value:"The flaw is caused by unspecified errors in the 'Extras Manager component'.");
  script_tag(name:"solution", value:"Upgrade to Skype version 4.1.0.179 or later.");
  script_tag(name:"summary", value:"The host is installed with Skype and is prone to unspecified
  vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.skype.com/intl/en/download/skype/windows/");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

skypeVer = get_kb_item("Skype/Win/Ver");
if(!skypeVer){
  exit(0);
}

if(!version_is_less(version:skypeVer, test_version:"4.1.0.179")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("Skype" >< name)
  {
    skypePath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!isnull(skypePath))
    {
      skypePath = skypePath + "Plugin Manager\skypePM.exe";
      share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:skypePath);
      file  =  ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:skypePath);

      ver = GetVer(file:file, share:share);
      if(ver != NULL)
      {
        if(version_is_less(version:ver, test_version:"2.0.0.67"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}
