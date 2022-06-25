###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_raidenftpd_server_detect.nasl 10886 2018-08-10 11:29:21Z cfischer $
#
# RaidenFTPD Server Version Detection
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900510");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10886 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 13:29:21 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("RaidenFTPD Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script finds the installed version of RaidenFTPD Server
  and sets the result in KB.");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("ftp_func.inc");
include("secpod_smb_func.inc");

SCRIPT_DESC = "RaidenFTPD Server Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

exePath = registry_get_sz(key:"SYSTEM\CurrentControlSet\Services" +
                              "\RaidenFTPDService", item:"ImagePath");
if(!exePath){
  exit(0);
}

exePath = exePath - "rftpdservice.exe" + "raidenftpd.exe";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);

rftpdVer = GetVer(file:file, share:share);
if(rftpdVer != NULL){
  set_kb_item(name:"RaidenFTPD/Ver", value:rftpdVer);
  log_message(data:"RaidenFTPD Server version " + rftpdVer + " running at" +
                     " location " + exePath +  " was detected on the host");

  cpe = build_cpe(value: rftpdVer, exp:"^([0-9.]+)",base:"cpe:/a:raidenftpd:raidenftpd:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

}
