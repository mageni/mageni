###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_rosoft_audio_converter_detect.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# Rosoft Audio Converter Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902078");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11015 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-06-22 14:43:46 +0200 (Tue, 22 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Rosoft Audio Converter Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This host is installed with Rosoft Audio Converter and sets the
  result in KB.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Rosoft Audio Converter Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item(registry_enum_keys(key:key))
{
  racName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Rosoft Audio Converter, Silver Edition, Release" >< racName)
  {
    racPath = registry_get_sz(key:key + item, item:"InstallLocation");

    racVer = eregmatch(pattern:"Release, ([0-9.]+)", string:racName);
    if(racVer[1] != NULL)
    {
      set_kb_item(name:"Rosoft/Audio/Converter/Ver", value:racVer[1]);
      log_message(data:"Rosoft Audio Converter version " + racVer[1] +
                     " running at location " + racPath + " was detected on the host");

      cpe = build_cpe(value:racVer[1], exp:"^([0-9.]+)", base:"cpe:/a:rosoftengineering:rosoft_audio_converter:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    }
  }
}

