###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_yahoo_msg_detect.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Yahoo! Messenger Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-07-02
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
  script_oid("1.3.6.1.4.1.25623.1.0.801149");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Yahoo! Messenger Version Detection");

  script_tag(name:"summary", value:"This script detects the installed version of Yahoo! Messenger and sets the
result in KB.

The script logs in via smb, search for the product name in the registry, gets
application Path from the registry and fetches the version from exe file.");

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
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Yahoo! Messenger");
  key_list2 = make_list("SOFTWARE\Yahoo\pager");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Yahoo! Messenger");
  key_list2 = make_list("SOFTWARE\Wow6432Node\Yahoo\pager");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  ymsgName = registry_get_sz(key:key, item:"DisplayName");

  if("Yahoo! Messenger" >< ymsgName)
  {
    ymsgPath = registry_get_sz(key:key, item:"DisplayIcon");
    ymsgPath = ymsgPath - "\YahooMessenger.exe,-0";

    foreach key1 (key_list2)
    {
      ymsgVer = registry_get_sz(key:key1, item:"ProductVersion");
      if(!ymsgVer)
      {
        ymsgVer = fetch_file_version(sysPath:ymsgPath, file_name:"YahooMessenger.exe");
      }
    }

    if(ymsgVer)
    {
      set_kb_item(name:"YahooMessenger/Ver", value:ymsgVer);
      register_and_report_cpe( app:"Yahoo Messenger", ver:ymsgVer, base:"cpe:/a:yahoo:messenger:", expr:"^([0-9.]+)", insloc:ymsgPath );
    }
  }
}
