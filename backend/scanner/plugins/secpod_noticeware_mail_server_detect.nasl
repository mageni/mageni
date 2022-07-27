###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_noticeware_mail_server_detect.nasl 10884 2018-08-10 11:02:52Z cfischer $
#
# NoticeWare Email Server Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900462");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10884 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 13:02:52 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("NoticeWare Email Server Version Detection");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed NoticeWare Email Server and
  saves the version in KB.");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("smtp_func.inc");
include("secpod_smb_func.inc");

SCRIPT_DESC = "NoticeWare Email Server Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\NoticeWare\EmailServer")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item(registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("NoticeWare Email Server" >< name)
  {
    ver = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(ver != NULL)
    {
      set_kb_item(name:"NoticeWare/Mail/Server/Ver", value:ver);
      log_message(data:"NoticeWare Email Server version " + ver +
                         " was detected on the host");

       cpe = build_cpe(value: ver, exp:"^([0-9.]+)",base:"cpe:/a:noticeware:noticeware_email_server_ng:");
       if(!isnull(cpe))
          register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

      exit(0);
    }
  }
}
