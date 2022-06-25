##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_multicash_detect_win.nasl 13105 2019-01-16 16:07:34Z mmartin $
#
# OMIKRON MultiCash Version Detection (Windows)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH, http//www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.107453");
  script_version("$Revision: 13105 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-16 17:07:34 +0100 (Wed, 16 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-16 17:06:59 +0100 (Wed, 16 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OMIKRON MultiCash Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version
  of OMIKRON MultiCash for Windows.");
  script_xref(name:"URL", value:"https://www.dzbank.de/content/dam/dzbank_de/de/home/produkte_services/Firmenkunden/PDF-Dokumente/transaction%20banking/elektronicBanking/5.05_DZB_PI_FK_GENO_Cash_2016-08-02.pdf");
  script_xref(name:"URL", value:"https://www.omikron.de/loesungen/unternehmen/multicash/");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
} else if("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)) exit(0);

foreach key (key_list) {
  foreach item (registry_enum_keys(key:key)) {

    appName = registry_get_sz(key:key + item, item:"DisplayName");
    # MultiCash is the Productbase of 'GENO cash'.

    if(!appName || appName !~ "GENO cash") continue;

    version = "unknown";
    concluded = appName;
    location = "unknown";

    loc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(loc) location = loc;

    version = registry_get_sz(key:key + item, item:"ProductVersion");

    set_kb_item(name:"omikron/multicash/win/detected", value:TRUE);

    register_and_report_cpe(app:"MultiCash " +appName , ver:version, concluded:concluded,
                          base:"cpe:/a:omikron:multicash:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0);
    exit(0);
  }
}

exit(0);
