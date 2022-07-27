###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_frontpage_detect.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Microsoft FrontPage Detection (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-06-24
# According to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803891");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-09-11 11:32:12 +0530 (Wed, 11 Sep 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft FrontPage Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Microsoft FrontPage.

The script logs in via smb, searches for Microsoft Office FrontPage and gets
the version from 'DisplayVersion' string in registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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
  key_list = make_list("SOFTWARE\Microsoft\Office");
  key_list2 = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Office");
  key_list2 = make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list && key_list2)){
  exit(0);
}


if(!registry_key_exists(key:"SOFTWARE\Microsoft\Office")){
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Microsoft\Office")){
    exit(0);
  }
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    if(eregmatch(pattern:"^([0-9.]+)" , string:item))
    {
      rootkey = key + "\" + item + "\FrontPage";
      if(!registry_key_exists(key: rootkey)){
        exit(0);
      }
      break;
    }
  }
}

foreach key (key_list2)
{
  foreach item (registry_enum_keys(key:key))
  {
    pageName = registry_get_sz(key:key + item, item:"DisplayName");
    if("Microsoft Office FrontPage" >< pageName)
    {

      insloc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insloc)
      {
        insloc = registry_get_sz(key: rootkey + "\InstallRoot", item:"Path");
        if(!insloc){
          insloc = "Unable to find the install location";
        }
      }

      pageVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      set_kb_item(name:"Microsoft/FrontPage/Ver", value:pageVer);
      register_and_report_cpe( app:pageName, ver:pageVer, base:"cpe:/a:microsoft:frontpage:", expr:"^([0-9.]+)", insloc:insloc );
    }
  }
}
