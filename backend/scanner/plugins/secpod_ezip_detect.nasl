###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ezip_detect.nasl 10905 2018-08-10 14:32:11Z cfischer $
#
# eZip Wizard Version Detection (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-05-20
# Updated according to CR57 and to support 32 and 64 bit.
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
  script_oid("1.3.6.1.4.1.25623.1.0.900524");
  script_version("$Revision: 10905 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:32:11 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-03-24 05:22:25 +0100 (Tue, 24 Mar 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("eZip Wizard Version Detection (Windows)");


  script_tag(name:"summary", value:"Detects the installed version of eZip Wizard on Windows.

The script logs in via smb, searches for eZip32 in the registry
and gets the version from the registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\ediSys\eZip32\";
}

## Presently eZip Wizard 64bit application is not available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\ediSys\eZip32\";
}

ezipVer = registry_get_sz(key:key, item:"Version");

if(ezipVer != NULL)
{
  appPath = "Could not find the install Location from registry";

  set_kb_item(name:"eZip/Version", value:ezipVer);

  cpe = build_cpe(value:ezipVer, exp:"^([0-9.]+)", base:"cpe:/a:edisys:ezip_wizard:");
  if(isnull(cpe))
    cpe = "cpe:/a:edisys:ezip_wizard";

  register_product(cpe:cpe, location:appPath);

  log_message(data: build_detection_report(app: "eZip Wizard",
                                           version: ezipVer,
                                           install: appPath,
                                           cpe: cpe,
                                           concluded: ezipVer));
}
