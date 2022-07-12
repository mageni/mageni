###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_detect_win.nasl 12413 2018-11-19 11:11:31Z cfischer $
#
# Adobe Products Version Detection (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900319");
  script_version("$Revision: 12413 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Products Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Adobe Products.

  The script logs in via smb, searches for Adobe Products in the registry
  and gets the version from 'DisplayVersion' string in registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

# nb: To make openvas-nasl-lint happy...
checkdupAcrbt = "";
checkdupAud = "";
checkdupRdr = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

syskey = "SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
if(!registry_key_exists(key:syskey)) {
  exit(0);
}

osArch = registry_get_sz(key:syskey, item:"PROCESSOR_ARCHITECTURE");
if(!osArch){
  exit(0);
}

if("x86" >< osArch){
 keylist = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("64" >< osArch)
{
  keylist =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(keylist)){
  exit(0);
}

foreach key (keylist)
{
  if(registry_key_exists(key:key))
  {
    foreach item (registry_enum_keys(key:key))
    {
      adobeName = registry_get_sz(key:key + item, item:"DisplayName");

      if((egrep(string:adobeName, pattern:"^(Adobe Reader)")) ||
         (egrep(string:adobeName, pattern:"^(Adobe Acrobat Reader)")))
      {
        readerVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        insPath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(readerVer != NULL && insPath)
        {

          if (readerVer + ", " >< checkdupRdr){
            continue;
          }

          checkdupRdr += readerVer + ", ";

          set_kb_item(name:"Adobe/Reader/Win/Installed", value:TRUE);
          set_kb_item(name:"Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed", value:TRUE);
          set_kb_item(name:"Adobe/Reader/Win/Ver", value:readerVer);
          register_and_report_cpe( app:adobeName, ver:readerVer, base:"cpe:/a:adobe:acrobat_reader:", expr:"^([0-9.]+)", insloc:insPath );

          if( "x64" >< osArch && "Wow6432Node" >!< key){
            set_kb_item(name:"Adobe/Reader64/Win/Ver", value:readerVer);
            register_and_report_cpe( app:adobeName, ver:readerVer, base:"cpe:/a:adobe:acrobat_reader:x64:", expr:"^([0-9.]+)", insloc:insPath );
          }
        }
      }

      else if(egrep(string:adobeName, pattern:"^(Adobe Acrobat)"))
      {
        acrobatVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        insPath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(acrobatVer != NULL && insPath)
        {
          if (acrobatVer + ", " >< checkdupAcrbt){
            continue;
          }

          checkdupAcrbt += acrobatVer + ", ";

          set_kb_item(name:"Adobe/Acrobat/Win/Installed", value:TRUE);
          set_kb_item(name:"Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed", value:TRUE);
          set_kb_item(name:"Adobe/Acrobat/Win/Ver", value:acrobatVer);
          register_and_report_cpe( app:adobeName, ver:acrobatVer, base:"cpe:/a:adobe:acrobat:", expr:"^([0-9.]+)", insloc:insPath );

          if( "x64" >< osArch && "Wow6432Node" >!< key){
            set_kb_item(name:"Adobe/Acrobat64/Win/Ver", value:acrobatVer);
            register_and_report_cpe( app:adobeName, ver:acrobatVer, base:"cpe:/a:adobe:acrobat:x64:", expr:"^([0-9.]+)", insloc:insPath );
          }
        }
      }
    }
  }
}

if("x86" >< osArch){
adkeylist = make_list("SOFTWARE\Adobe\Audition\");
}

else if("64" >< osArch)
{
  adkeylist =  make_list("SOFTWARE\Adobe\Audition\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (adkeylist)
{
  if(registry_key_exists(key:key))
  {
    foreach item (registry_enum_keys(key:key))
    {
      audName = registry_get_sz(key:key + item, item:"DisplayName");

      if(egrep(string:audName, pattern:"^(Adobe Audition)"))
      {
        audVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        insPath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(audVer != NULL && insPath)
        {
          if (audVer + ", " >< checkdupAud){
            continue;
          }

          checkdupAud  += audVer + ", ";
          set_kb_item(name:"Adobe/Audition/Win/Installed", value:TRUE);
          set_kb_item(name:"Adobe/Audition/Win/Ver", value:audVer);
          register_and_report_cpe( app:audName, ver:audVer, base:"cpe:/a:adobe:audition:", expr:"^([0-9.]+)", insloc:insPath );

          if( "x64" >< osArch && "Wow6432Node" >!< key){
            set_kb_item(name:"Adobe/Audition64/Win/Ver", value:audVer);
            register_and_report_cpe( app:audName, ver:audVer, base:"cpe:/a:adobe:audition:x64:", expr:"^([0-9.]+)", insloc:insPath );
          }
        }
      }
    }
  }
}
