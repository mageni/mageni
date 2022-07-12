###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ejabberd_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# ejabberd Version Detection (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-05-28
# According to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902529");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ejabberd Version Detection (Windows)");

  script_tag(name:"summary", value:"This script finds the installed ejabberd version and saves the version in
KB.

The script logs in via smb, searches for ejabberd in the registry and gets the
version from 'Version' string from the registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\ProcessOne\ejabberd");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Wow6432Node\ProcessOne\ejabberd");
}

if(isnull(key_list)){
    exit(0);
}

key = "SOFTWARE\ProcessOne\ejabberd";
key1 = "SOFTWARE\Wow6432Node\ProcessOne\ejabberd";

if(!registry_key_exists(key:key))
{
  if(!registry_key_exists(key:key1))
  {
    exit(0);
  }
}

foreach key (key_list)
{
  ejVer = registry_get_sz(key:key, item:"Version");

  if(ejVer)
  {
    ejPath = registry_get_sz(key:key, item:"Location");
    if(!ejPath){
      ejPath = "Couldn find the install location from registry";
    }

    set_kb_item(name:"ejabberd/Win/Ver", value:ejVer);

    cpe = build_cpe(value:ejVer, exp:"^([0-9.]+)", base:"cpe:/a:process-one:ejabberd:");
    if(isnull(cpe))
      cpe = "cpe:/a:process-one:ejabberd";

    register_product(cpe:cpe, location:ejPath);
    log_message(data: build_detection_report(app: "ejabberd",
                                             version:ejVer,
                                             install: ejPath ,
                                             cpe:cpe,
                                             concluded:ejVer));
  }
}
