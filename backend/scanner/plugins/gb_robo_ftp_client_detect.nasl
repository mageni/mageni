##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_robo_ftp_client_detect.nasl 10883 2018-08-10 10:52:12Z cfischer $
#
# Robo-FTP Client Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801053");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10883 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 12:52:12 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-12-02 13:54:57 +0100 (Wed, 02 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Robo-FTP Client Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script finds the installed Robo-FTP Client version and saves the
  result in KB item.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("Robo-FTP" >< name)
  {
    ftpVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!isnull(ftpVer))
    {
      set_kb_item(name:"Robo/FTP/Ver", value:ftpVer);

      register_and_report_cpe(app:"Robo-FTP Client", ver:ftpVer, base:"cpe:/a:robo-ftp:robo-ftp:",
                              expr:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?");
      exit(0);
    }
  }
}

path = registry_get_sz(key:"SOFTWARE\Robo-FTP", item:"InstallDir");
if(path != NULL)
{
  ftpVer = fetch_file_version(sysPath:path, file_name:"Robo-FTP.exe");
  if(!isnull(ftpVer))
  {
    set_kb_item(name:"Robo/FTP/Ver", value:ftpVer);

    register_and_report_cpe(app:"Robo-FTP Client", ver:ftpVer, base:"cpe:/a:robo-ftp:robo-ftp:",
                            expr:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", insloc:path);
    exit(0);
  }
}
