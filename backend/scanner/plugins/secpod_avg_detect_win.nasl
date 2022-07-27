###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_avg_detect_win.nasl 11420 2018-09-17 06:33:13Z cfischer $
#
# AVG AntiVirus Version Detection (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http//www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900718");
  script_version("$Revision: 11420 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 08:33:13 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-05-29 07:35:11 +0200 (Fri, 29 May 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("AVG AntiVirus Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version of AVG AntiVirus

  The script logs in via smb, searches for AVG AntiVirus in the registry
  and gets the version from registry");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\AVG")){
  exit(0);
}

foreach ver (make_list("1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "2012", "2013"))
{
  avgVer = registry_get_sz(key:"SOFTWARE\AVG\AVG" + ver +
                               "\LinkScanner\Prevalence", item:"CODEVER");

  avgPath = registry_get_sz(key:"SOFTWARE\AVG\AVG" + ver +
                               "\LinkScanner", item:"AppPath");
  if(!avgPath){
    avgPath = "Could not find the install location from registry";
  }

  if(avgVer)
  {
    set_kb_item(name:"AVG/AV/Win/Ver", value:avgVer);
    register_and_report_cpe(app:"AVG Antivirus", ver:avgVer, base:"cpe:/a:avg:avg_anti-virus:",
                            expr:"^([0-9.]+)", insloc:avgPath, concluded:avgVer);
    exit(0);

  }
}

if(!avgVer)
{
  ## Key for AVG Antivirus Free 2017
  key = "SOFTWARE\AVG\Antivirus";

  if(!registry_key_exists(key:key)){
    exit(0);
  }

  avgVer = registry_get_sz(key:key, item:"Version");

  avgPath = registry_get_sz(key:key, item:"DataFolder");
  if(!avgPath){
    avgPath = "Could not find the install location from registry";
  }

  if(avgVer)
  {
    set_kb_item(name:"AVG/AV/Win/Ver", value:avgVer);
    register_and_report_cpe(app:"AVG Antivirus", ver:avgVer, base:"cpe:/a:avg:avg_anti-virus:",
                            expr:"^([0-9.]+)", insloc:avgPath, concluded:avgVer);
    exit(0);
  }
}
