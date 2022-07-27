##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panda_prdts_detect.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Panda Products Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-07-15
# According to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801079");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-12-14 09:18:47 +0100 (Mon, 14 Dec 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Panda Products Version Detection");

  script_tag(name:"summary", value:"This script finds the installed Panda Products and saves the version in KB.

The script logs in via smb, searches for Panda Global Protection, Panda Internet
Security and Panda Antivirus in the registry and gets the version from registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Panda Software")){
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Panda Software")){
    exit(0);
  }
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    avName = registry_get_sz(key:key + item, item:"DisplayName");
    ##  Check for the Internet Security

    if("Panda Gold Protection" >< avName)
    {
      pandaVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      pandaPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(pandaVer != NULL)
      {
        set_kb_item(name:"Panda/Products/Installed", value:TRUE);
        set_kb_item(name:"Panda/GoldProtection/Ver", value:pandaVer);
        register_and_report_cpe( app:"Panda Gold Protection", ver:pandaVer, base:"cpe:/a:pandasecurity:panda_gold_protection:", expr:"^([0-9.]+)", insloc:pandaPath );
      }
    }

    if("Small Business Protection" >< avName)
    {
      pandaVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      pandaPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(pandaVer != NULL)
      {
        set_kb_item(name:"Panda/Products/Installed", value:TRUE);
        set_kb_item(name:"Panda/SmallBusinessProtection/Ver", value:pandaVer);
        if(pandaVer =~ "^(16|17\.0)")
        {
          register_and_report_cpe( app:"Panda Small Business Protection", ver:pandaVer, base:"cpe:/a:pandasecurity:panda_small_business_protection:", expr:"^([0-9.]+)", insloc:pandaPath );
        }
      }
    }

    if("Panda Internet Security" >< avName)
    {
      pandaVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      pandaPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(pandaVer != NULL)
      {
        set_kb_item(name:"Panda/Products/Installed", value:TRUE);
        set_kb_item(name:"Panda/InternetSecurity/Ver", value:pandaVer);
        if(pandaVer =~ "^(16|17|19\.0)")
        {
          register_and_report_cpe( app:"Panda Internet Security", ver:pandaVer, base:"cpe:/a:pandasecurity:panda_internet_security_2014:", expr:"^([0-9.]+)", insloc:pandaPath );
        }

        if(pandaVer =~ "^(15\.0)")
        {
          register_and_report_cpe( app:"Panda Internet Security", ver:pandaVer, base:"cpe:/a:pandasecurity:panda_internet_security_2010:", expr:"^([0-9.]+)", insloc:pandaPath );
        }
      }
    }

    ##  Check for the Global Protection
    if("Panda Global Protection" >< avName)
    {
      pandaVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      pandaPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(pandaVer != NULL)
      {
        set_kb_item(name:"Panda/Products/Installed", value:TRUE);
        set_kb_item(name:"Panda/GlobalProtection/Ver", value:pandaVer);
        if(pandaVer =~ "^(3\.0)")
        {
          register_and_report_cpe( app:"Panda Global Protection", ver:pandaVer, base:"cpe:/a:pandasecurity:panda_global_protection_2010:", expr:"^([0-9.]+)", insloc:pandaPath );
        }

        if(pandaVer =~ "^(16|17|7\.0)")
        {
          register_and_report_cpe( app:"Panda Global Protection", ver:pandaVer, base:"cpe:/a:pandasecurity:panda_global_protection_2014:", expr:"^([0-9.]+)", insloc:pandaPath );
        }
      }
    }

    ##  Check for the Antivirus
    if("Panda Antivirus" >< avName)
    {
      pandaVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      pandaPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(pandaVer != NULL)
      {
        set_kb_item(name:"Panda/Products/Installed", value:TRUE);
        set_kb_item(name:"Panda/Antivirus/Ver", value:pandaVer);
        if(pandaVer =~ "^(9\.0)")
        {
          register_and_report_cpe( app:"Panda Antivirus", ver:pandaVer, base:"cpe:/a:pandasecurity:panda_av_pro_2010:", expr:"^([0-9.]+)", insloc:pandaPath );
        }

        if(pandaVer =~ "^(16|17|13\.0)")
        {
          register_and_report_cpe( app:"Panda Antivirus", ver:pandaVer, base:"cpe:/a:pandasecurity:panda_av_pro_2014:", expr:"^([0-9.]+)", insloc:pandaPath );
        }
      }
    }
  }
}
