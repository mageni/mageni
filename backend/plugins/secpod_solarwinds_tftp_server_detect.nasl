# Copyright (C) 2009 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900930");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-09-01T12:57:33+0000");
  script_tag(name:"last_modification", value:"2021-09-03 12:13:43 +0000 (Fri, 03 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SolarWinds TFTP Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects installed version of SolarWinds TFTP Server.");
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
