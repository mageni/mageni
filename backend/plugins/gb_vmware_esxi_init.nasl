###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_esxi_init.nasl 13247 2019-01-23 15:12:20Z cfischer $
#
# VMware ESXi scan initialization.
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103447");
  script_version("$Revision: 13247 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-23 16:12:20 +0100 (Wed, 23 Jan 2019) $");
  script_tag(name:"creation_date", value:"2012-03-14 14:54:53 +0100 (Wed, 14 Mar 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("VMware ESXi scan initialization");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esx_web_detect.nasl", "gb_esxi_authorization.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("VMware/ESX/typ/ESXi", "VMware/ESX/port");

  script_add_preference(name:"ESXi login name:", type:"entry", value:"");
  script_add_preference(name:"ESXi login password:", type:"password", value:"");

  script_tag(name:"summary", value:"This NVT initiate an authenticated scan against ESXi and store some results in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("vmware_esx.inc");
include("host_details.inc");

port = get_kb_item("VMware/ESX/port");
if(!port || !get_port_state(port)) {
  exit(0);
}

user = get_kb_item("esxi/login_filled/0");
if( ! user )
  user = script_get_preference("ESXi login name:");

pass = get_kb_item("esxi/password_filled/0");
if( ! pass )
  pass = script_get_preference("ESXi login password:");

if( ! user || ! pass ) {
  exit(0);
}

esxi_version = get_kb_item("VMware/ESX/version");

if(!esxi_version) {
  log_message(data:string("It was NOT possible to retrieve the ESXi version. Local Security Checks for ESXi disabled.\n"));
  exit(0);
}

if(esxi_version !~ "^4\." && esxi_version !~ "^5\." && esxi_version !~ "^6\.") {
  log_message(data:string("Unsupported ESXi version. Currently ESXi 4.0, 4.1 and 5.0, 5.1, 5.5, 6.0 and 6.5 are supported. We found ESXi version ", esxi_version, "\n"));
  register_host_detail(name:"Auth-ESXi-Failure", value:"Protocol ESXi, Port " + port + ", User " + user + " : Unsupported ESXi version.");
  exit(0);
}

if(esxi_version =~ "^4\.") {
  if(get_esxi4_x_vibs(port:port, user:user, pass:pass)) {
    set_kb_item(name:"VMware/ESXi/LSC", value:TRUE);
    set_kb_item(name:"login/ESXi/success", value:TRUE);
    set_kb_item(name:"login/ESXi/success/port", value:port);
    log_message(data:string("It was possible to login and to get all relevant information. Local Security Checks for ESXi 4.x enabled.\n\nWe found the following bulletins installed on the remote ESXi:\n", installed_bulletins,"\n"), port:port);
    register_host_detail(name:"Auth-ESXi-Success", value:"Protocol ESXi, Port " + port + ", User " + user);
    exit(0);
  } else {
    set_kb_item(name:"login/ESXi/failed", value:TRUE);
    set_kb_item(name:"login/ESXi/failed/port", value:port);
    log_message(data:string("It was NOT possible to login and to get all relevant information. Local Security Checks for ESXi 4.x disabled.\n\nError: ", esxi_error,"\n"), port:port);
    register_host_detail(name:"Auth-ESXi-Failure", value:"Protocol ESXi, Port " + port + ", User " + user + " : Login failure");
    exit(0);
  }
}

if(esxi_version =~ "^(5|6)\.") {
  if(get_esxi5_0_vibs(port:port, user:user, pass:pass)) {
    set_kb_item(name:"VMware/ESXi/LSC", value:TRUE);
    set_kb_item(name:"login/ESXi/success", value:TRUE);
    set_kb_item(name:"login/ESXi/success/port", value:port);
    log_message(data:string("It was possible to login and to get all relevant information. Local Security Checks for ESXi 5.x/6.x enabled.\n\nWe found the following bulletins installed on the remote ESXi:\n", installed_bulletins,"\n"), port:port);
    register_host_detail(name:"Auth-ESXi-Success", value:"Protocol ESXi, Port " + port + ", User " + user);
    exit(0);
  } else {
    set_kb_item(name:"login/ESXi/failed", value:TRUE);
    set_kb_item(name:"login/ESXi/failed/port", value:port);
    log_message(data:string("It was NOT possible to login and to get all relevant information. Local Security Checks for ESXi 5.x/6.x disabled.\n\nError: ", esxi_error,"\n"), port:port);
    register_host_detail(name:"Auth-ESXi-Failure", value:"Protocol ESXi, Port " + port + ", User " + user + " : Login failure");
    exit(0);
  }
}

exit(0);