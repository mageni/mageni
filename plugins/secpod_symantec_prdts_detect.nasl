###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_symantec_prdts_detect.nasl 14328 2019-03-19 13:54:40Z cfischer $
#
# Symantec Product(s) Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Update By: Antu Sanadi <santu@secpod.com> on 2010-02-25
# Updated to detect and set KB for EndPoint Protection IM Manager
#
# Update By: Sooraj KS <kssooraj@secpod.com> on 2011-02-01
# Updated to detect Symantec AntiVirus Corporate Edition
#
# Update By:  Rachana Shetty <srachana@secpod.com> on 2012-03-03
# Updated to detect Symantec Norton AntiVirus and according to CR-57
# On 2012-11-23 to detect SEPSBE
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-09-02
# To support 32 and 64 bit.
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
  script_oid("1.3.6.1.4.1.25623.1.0.900332");
  script_version("2019-04-04T14:50:45+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-04-04 14:50:45 +0000 (Thu, 04 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-03-30 15:53:34 +0200 (Mon, 30 Mar 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Symantec Product(s) Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Symantec Product(s).

  The script logs in via smb, searches for Symantec Product(s) in the registry
  and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
  key_list2 = make_list("SOFTWARE\Symantec\Symantec Endpoint Protection\SEPM");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
  key_list2  = make_list("SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\SEPM");
}

foreach symkey(key_list)
{
  foreach item(registry_enum_keys(key:symkey))
  {
    symantecName = registry_get_sz(key:symkey + item, item:"DisplayName");

    if("Norton AntiVirus" >< symantecName)
    {
      navVer = registry_get_sz(key:symkey + item, item:"DisplayVersion");
      if(navVer)
      {
        set_kb_item(name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE);
        set_kb_item(name:"Symantec/Norton-AV/Ver", value:navVer);

        navPath = registry_get_sz(key: symkey + item, item:"InstallLocation");
        if(! navPath){
          navPath = "Could not find the install Location from registry";
        }
        register_and_report_cpe( app:symantecName, ver:navVer, concluded:navVer, base:"cpe:/a:symantec:norton_antivirus:", expr:"^([0-9.]+)", insloc:navPath );
      }
    }

    if("Norton Internet Security" >< symantecName)
    {
      nisVer = registry_get_sz(key:symkey + item, item:"DisplayVersion");
      if(nisVer)
      {
        set_kb_item(name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE);
        set_kb_item(name:"Norton/InetSec/Ver", value:nisVer);

        nisPath = registry_get_sz(key:symkey + item, item:"InstallLocation");
        if(! nisPath){
          nisPath = "Could not find the install Location from registry";
        }
        register_and_report_cpe( app:symantecName, ver:nisVer, concluded:nisVer, base:"cpe:/a:symantec:norton_internet_security:", expr:"^([0-9.]+)", insloc:nisPath );
      }
    }

    if("Symantec pcAnywhere" >< symantecName)
    {
      pcawVer = registry_get_sz(key:symkey + item, item:"DisplayVersion");
      if(pcawVer)
      {
        set_kb_item(name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE);
        set_kb_item(name:"Symantec/pcAnywhere/Ver", value:pcawVer);

        pcawPath = registry_get_sz(key:symkey + item, item:"InstallLocation");
        if(! pcawPath){
          pcawPath = "Could not find the install Location from registry";
        }
        register_and_report_cpe( app:symantecName, ver:pcawVer, concluded:pcawVer, base:"cpe:/a:symantec:pcanywhere:", expr:"^([0-9.]+)", insloc:pcawPath );
      }
    }

    if("Enterprise Security Manager" >< symantecName)
    {
      esmVer = registry_get_sz(key:symkey + item, item:"DisplayVersion");
      if(esmVer)
      {
        set_kb_item(name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE);
        set_kb_item(name:"Symantec/ESM/Ver", value:esmVer);
        set_kb_item(name:"Symantec/ESM/Component", value:symantecName);

        esmPath = registry_get_sz(key:symkey + item, item:"InstallLocation");
        if(! esmPath){
          esmPath = "Could not find the install Location from registry";
        }

        set_kb_item(name:"Symantec/ESM/Path", value:esmPath);
        register_and_report_cpe( app:symantecName, ver:esmVer, concluded:esmVer, base:"cpe:/a:symantec:enterprise_security_manager:", expr:"^([0-9.]+)", insloc:esmPath );
      }
    }

    ## Symantec AntiVirus Corporate Edition, this product is Discontinued.
    if("Symantec AntiVirus" >< symantecName)
    {
      savceVer = registry_get_sz(key:symkey + item, item:"DisplayVersion");
      if(savceVer)
      {
        set_kb_item(name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE);
        set_kb_item(name:"Symantec/SAVCE/Ver", value:savceVer);

        savcePath = registry_get_sz(key:symkey + item, item:"InstallLocation");
        if(! savcePath){
          savcePath = "Could not find the install Location from registry";
        }
        register_and_report_cpe( app:symantecName, ver:savceVer, concluded:savceVer, base:"cpe:/a:symantec:antivirus:", expr:"^([0-9.]+)", insloc:savcePath );
      }
    }

    ## IMManager- this product is Discontinued
    if("IMManager" >< symantecName)
    {
      imPath = registry_get_sz(key:symkey + item, item:"InstallSource");
      if(imPath)
      {
        imPath = imPath - "\temp";
        imVer = fetch_file_version(sysPath:imPath, file_name:"IMLogicAdminService.exe");

        if(imVer)
        {
          set_kb_item(name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE);
          set_kb_item(name:"Symantec/IM/Manager", value:imVer);
          register_and_report_cpe( app:symantecName, ver:imVer, concluded:imVer, base:"cpe:/a:symantec:im_manager:", expr:"^([0-9.]+)", insloc:imPath );
        }
      }
    }
  }
}

foreach symkey(key_list2)
{
  if(registry_key_exists(key:symkey))
  {
    nisVer = registry_get_sz(key:symkey, item:"Version");
    if(nisVer)
    {
      set_kb_item(name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE);
      set_kb_item(name:"Symantec/Endpoint/Protection", value:nisVer);

      nisPath = registry_get_sz(key:symkey + item, item:"TargetDir");
      if(! nisPath){
        nisPath = "Could not find the install Location from registry";
      }

      # nb: ProductType sepsb: (Symantec Endpoint Protection Small Businees)
      nisType = registry_get_sz(key:symkey, item:"ProductType");
      if(nisType && "sepsb" >< nisType)
      {
        set_kb_item(name:"Symantec/SEP/SmallBusiness", value:nisType);
        base = "cpe:/a:symantec:endpoint_protection:" + nisVer + ":small_business";
      } else{
        base = "cpe:/a:symantec:endpoint_protection:";
      }
      register_and_report_cpe( app:"Symantec Endpoint Protection", ver:nisVer, concluded:nisVer, base:base, expr:"^([0-9.]+)", insloc:nisPath );
    }
  }
}
