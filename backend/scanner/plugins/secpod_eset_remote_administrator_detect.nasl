###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_eset_remote_administrator_detect.nasl 10884 2018-08-10 11:02:52Z cfischer $
#
# ESET Remote Administrator Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900508");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10884 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 13:02:52 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("ESET Remote Administrator Version Detection");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed
  version of ESET Remote Administrator and saves the version in KB.");
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(registry_key_exists(key:"SOFTWARE\ESET\ESET Remote Administrator\Console"))
{
  consoleVer = registry_get_sz(key:"SOFTWARE\ESET\ESET Remote Administrator" +
                                   "\Console\CurrentVersion\Info",
                               item:"ProductVersion");
  if(consoleVer != NULL){
    set_kb_item(name:"ESET/RemoteAdmin/Console_or_Server/Installed", value:TRUE);
    set_kb_item(name:"ESET/RemoteAdmin/Console/Ver", value:consoleVer);

    register_and_report_cpe(app:"ESET Remote Administrator Console", ver:consoleVer,
                            base:"cpe:/a:eset:remote_administrator:", expr:"^([0-9.]+)");
  }
}

if(registry_key_exists(key:"SOFTWARE\ESET\ESET Remote Administrator\Server"))
{
  servVer = registry_get_sz(key:"SOFTWARE\ESET\ESET Remote Administrator" +
                                "\Server\CurrentVersion\Info",
                            item:"ProductVersion");
  if(servVer != NULL){
    set_kb_item(name:"ESET/RemoteAdmin/Console_or_Server/Installed", value:TRUE);
    set_kb_item(name:"ESET/RemoteAdmin/Server/Ver", value:servVer);

    register_and_report_cpe(app:"ESET Remote Administrator Console", ver:servVer,
                            base:"cpe:/a:eset:remote_administrator:", expr:"^([0-9.]+)");
  }

}

