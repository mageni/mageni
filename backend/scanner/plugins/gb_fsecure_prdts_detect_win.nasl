###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fsecure_prdts_detect_win.nasl 10883 2018-08-10 10:52:12Z cfischer $
#
# F-Secure Multiple Products Version Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800355");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10883 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 12:52:12 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-03-13 14:39:10 +0100 (Fri, 13 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("F-Secure Multiple Products Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"The script detects the installed version of F-Secure Anti-Virus
  (for MS Exchange), Workstations and Internet GateKeeper & sets the version
  in KB.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Data Fellows\F-Secure")){
  exit(0);
}

fsavVer = registry_get_sz(key:"SOFTWARE\Data Fellows\F-Secure\Anti-Virus",
                          item:"CurrentVersionEx");
if(fsavVer)
{
  set_kb_item(name:"F-Sec/AV/Win/Ver", value:fsavVer);

  register_and_report_cpe(app:"F-secure Anti Virus", ver:fsavVer, base:"cpe:/a:f-secure:f-secure_anti-virus:",
                          expr:"^([0-9]+\.[0-9]+)");
}

fsigkVer = registry_get_sz(key:"SOFTWARE\Data Fellows\F-Secure" +
                               "\Anti-Virus for Internet Gateways",
                           item:"CurrentVersion");
if(fsigkVer)
{
  set_kb_item(name:"F-Sec/AV/IntGatekeeper/Win/Ver", value:fsigkVer);

  register_and_report_cpe(app:"F-secure Anti Virus Intrnet Gate Keeper", ver:fsigkVer,
                          base:"cpe:/a:f-secure:f-secure_internet_gatekeeper_for_windows:",
                          expr:"^([0-9]+\.[0-9]+)");
}

fsavmeVer = registry_get_sz(key:"SOFTWARE\Data Fellows\F-Secure" +
                                "\Anti-Virus Agent for Microsoft Exchange",
                            item:"CurrentVersion");
if(fsavmeVer)
{
  set_kb_item(name:"F-Sec/AV/MSExchange/Ver", value:fsavmeVer);

  register_and_report_cpe(app:"F-secure Anti Virus MS Exhange", ver:fsavmeVer,
                          base:"cpe:/a:f-secure:f-secure_anti-virus_for_microsoft_exchange:",
                          expr:"^([0-9]+\.[0-9]+)");

}

fsavcsVer = registry_get_sz(key:"SOFTWARE\Data Fellows\F-Secure\FSAVCSIN",
                            item:"CurrentVersion");
if(fsavcsVer)
{
  set_kb_item(name:"F-Sec/AV/ClientSecurity/Ver", value:fsavcsVer);

  register_and_report_cpe(app:"F-secure Anti Virus Client Security", ver:fsavcsVer,
                          base:"cpe:/a:f-secure:f-secure_client_security:",
                          expr:"^([0-9]+\.[0-9]+)");
}

fsavwsKey = "SOFTWARE\Data Fellows\F-Secure\TNB\Products\";
foreach item (registry_enum_keys(key:fsavwsKey))
{
  fsavwsName = registry_get_sz(key:fsavwsKey + item, item:"ProductName");

  if("F-Secure Anti-Virus for Windows Servers" >< fsavwsName)
  {
    fsavwsVer = registry_get_sz(key:fsavwsKey + item, item:"Version");
    if(fsavwsVer)
    {
      set_kb_item(name:"F-Sec/AV/WindowsServers/Ver", value:fsavwsVer);

      register_and_report_cpe(app:"F-secure Anti Virus Windows Server", ver:fsavwsVer,
                          base:"cpe:/a:f-secure:f-secure_anti-virus_for_windows_servers:",
                          expr:"^([0-9]+\.[0-9]+)");
    }
  }
}
