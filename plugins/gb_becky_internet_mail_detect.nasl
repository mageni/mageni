###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_becky_internet_mail_detect.nasl 10884 2018-08-10 11:02:52Z cfischer $
#
# Becky Internet Mail Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800518");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10884 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 13:02:52 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Becky Internet Mail Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the version of Becky Internet Mail and
  sets the result in KB.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Becky Internet Mail Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  if("Becky!" >< registry_get_sz(key:key + item, item:"DisplayName"))
  {
    path = registry_get_sz(key:key + item, item:"DisplayIcon");
    if(path != NULL)
    {
      bimPath = ereg_replace(pattern:'\"(.*)\".*', replace:"\1", string:path);
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:bimPath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:bimPath);
      bimVer = GetVer(share:share, file:file);
      if(bimVer)
      {
        set_kb_item(name:"Becky/InternetMail/Ver", value: bimVer);
        log_message(data:"Becky Internet Mail version " + bimVer + " running" +
                           " at location " + bimPath + " was detected on the host");

        cpe = build_cpe(value:bimVer, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:rimarts_inc.:becky_internet_mail:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

      }
    }
    exit(0);
  }
}
