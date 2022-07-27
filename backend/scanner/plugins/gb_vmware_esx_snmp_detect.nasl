###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_esx_snmp_detect.nasl 10896 2018-08-10 13:24:05Z cfischer $
#
# VMware ESX detection (SNMP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.103417");
  script_version("$Revision: 10896 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:24:05 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-02-14 10:38:50 +0100 (Tue, 14 Feb 2012)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("VMware ESX detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_xref(name:"URL", value:"http://www.vmware.com/");

  script_tag(name:"summary", value:"This host is running VMware ESX(i).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "VMware ESX detection (SNMP)";

include("snmp_func.inc");

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc || "vmware" >!< tolower(sysdesc))exit(0);

version = eregmatch(pattern:"(VMware ESX ?(Server)?) ([0-9.]+)",string:sysdesc);

if(!isnull(version[1]) && !isnull(version[3])) {

  typ = version[1];
  vers = version[3];

  if(vers > 0) {
    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/o:vmware:esx:"); # even if it is an "ESXi", there is just "ESX" in sysdescr.
    set_kb_item(name:"VMware/GSX-Server/snmp/version",value:vers);
  } else {
    cpe = "cpe:/o:vmware:esx";
    set_kb_item(name:"VMware/GSX-Server/snmp/version",value:"unknown");
    vers = "unknown";
  }

  register_and_report_os( os:"VMware ESX(i)", cpe:cpe, banner_type:"SNMP sysdesc", banner:sysdesc, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );

  set_kb_item(name:"VMware/ESX/installed",value:TRUE);

  if("build" >< sysdesc) {
    build = eregmatch(pattern:" build-([0-9]+)",string:sysdesc);
    if(!isnull(build[1])) {
      replace_kb_item(name:"VMware/ESX/build", value:build[1]);
    }
  }

  result_txt = 'Detected ' + typ  + ' Version: ';
  result_txt += vers;
  result_txt += '\nCPE: '+ cpe;
  result_txt += '\n\nConcluded from remote snmp sysDescr:\n';
  result_txt += sysdesc;
  result_txt += '\n';

  log_message(port:port, data:result_txt, proto:"udp");

  exit(0);

}
