##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_solarwinds_tftp_server_detect.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# SolarWinds TFTP Server Version Detection
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900930");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SolarWinds TFTP Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects installed version of SolarWinds TFTP Server
  and sets the result in KB.");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

SCRIPT_DESC = "SolarWinds TFTP Server Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

stftpKey = "SOFTWARE\";
foreach item(registry_enum_keys(key:stftpKey))
{
  if("SolarWinds" >< item)
  {
    stftpPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                                item:"ProgramFilesDir");
    if(stftpPath != NULL)
    {
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:stftpPath);
      file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",  string:stftpPath +
                                         "\SolarWinds\TFTPServer\TFTPServer.exe");
      stftpVer = GetVer(share:share, file:file);
      if(isnull(stftpVer))
      {
        file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:stftpPath +
                                        "\SolarWinds\Free Tools\TFTP-Server.exe");
        stftpVer = GetVer(share:share, file:file);
      }
      if(stftpVer){
        set_kb_item(name:"SolarWinds/TFTP/Ver", value:stftpVer);
        log_message(data:"SolarWinds TFTP Server version " + stftpVer +
                           " was detected on the host");

        cpe = build_cpe(value: stftpVer, exp:"^([0-9.]+)",base:"cpe:/a:solarwinds:tftp_server:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

      }
    }
  }
}
