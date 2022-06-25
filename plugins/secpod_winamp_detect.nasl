###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_winamp_detect.nasl 10922 2018-08-10 19:21:48Z cfischer $
#
# Winamp Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-09-02
# According to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900196");
  script_version("$Revision: 10922 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 21:21:48 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-01-29 15:16:47 +0100 (Thu, 29 Jan 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Winamp Version Detection");


  script_tag(name:"summary", value:"Detects the installed version of Winamp.

The script logs in via smb, searches for the installed version of Winamp
in registry and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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

## Key is independent of architecture
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\winamp.exe";

if(isnull(key)){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\winamp.exe")){
  exit(0);
}

winampPath = registry_get_sz(key:key, item:"Path");
if(!winampPath){
  exit(0);
}

winampVer = fetch_file_version(sysPath:winampPath , file_name:"winamp.exe");

if(winampVer)
{
  set_kb_item(name:"Winamp/Version", value:winampVer);

  cpe = build_cpe(value:winampVer, exp:"^([0-9.]+)", base:"cpe:/a:nullsoft:winamp:");
  if(isnull(cpe))
    cpe = "cpe:/a:nullsoft:winamp";

  register_product(cpe:cpe, location:winampPath);

  log_message(data: build_detection_report(app:"Winamp",
                                           version:winampVer,
                                           install:winampPath,
                                           cpe:cpe,
                                           concluded:winampVer));
}
