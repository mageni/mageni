###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bpftp_detect.nasl 10884 2018-08-10 11:02:52Z cfischer $
#
# BulletProof FTP Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800329");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10884 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 13:02:52 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-01-06 15:38:06 +0100 (Tue, 06 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("BulletProof FTP Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script finds the installed BulletProof FTP Version and
  saves the version in KB.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "BulletProof FTP Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
      "\BulletProof FTP Client_is1";
if("BulletProof FTP Client" >< registry_get_sz(key:key, item:"DisplayName"))
{
  exePath = registry_get_sz(key:key, item:"DisplayIcon");
  if(!exePath){
    exit(0);
  }
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);

  bpftpVer = GetVer(file:file, share:share);

  if(bpftpVer)
  {
    set_kb_item(name:"BulletProof/Client/Ver", value:bpftpVer);
    log_message(data:"Bullet Proof FTP Client version " + bpftpVer + " running"+
                       " at location " + exePath + " was detected on the host");

    cpe = build_cpe(value:bpftpVer, exp:"^([0-9.]+)", base:"cpe:/a:bpftp:bulletproof_ftp_client:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  }
}
