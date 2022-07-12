###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_S7_1200_plc_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Siemens SIMATIC S7-1200 PLC Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103583");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-10-10 11:28:02 +0200 (Wed, 10 Oct 2012)");
  script_name("Siemens SIMATIC S7-1200 PLC Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "gb_snmp_sysdesc.nasl");
  script_require_ports("Services/www", 80);
  script_require_udp_ports("Services/udp/snmp", 161);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"Detection of Siemens SIMATIC S7-1200 PLC.

 The script sends a connection request to the server and attempts to
 extract the version number from the reply.

 This NVT has been replaced by NVTs gb_simatic_s7_version.nasl (OID:1.3.6.1.4.1.25623.1.0.106096)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"deprecated", value:TRUE);
  exit(0);
}

exit(66);

include("http_func.inc");
include("http_keepalive.inc");

include("cpe.inc");
include("host_details.inc");

function report_simatic_version(vers,install,concluded,port) {

   local_var vers,install,concluded,port;

   set_kb_item(name:"simatic_s7_1200/installed", value:TRUE);

   cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/h:siemens:simatic_s7-1200_plc:");
   if(isnull(cpe))
     cpe = 'cpe:/h:siemens:simatic_s7-1200_plc';

   register_product(cpe:cpe, location:install, port:port);

   log_message(data: build_detection_report(app:"Siemens SIMATIC S7-1200 PLC", version:vers, install:port, cpe:cpe, concluded: concluded),
               port:port);

   exit(0);

}


port = 161;

if(get_port_state(port)) {

  sysdesc = get_kb_item("SNMP/" + port + "/sysdesc");

  if("SIMATIC S7, CPU-1200" >< sysdesc) {

    sp = split(sysdesc,sep:",", keep:FALSE);

    if(!isnull(sp[5])) {
      version = eregmatch(pattern:"V\.([0-9.]+)", string: sp[5]);
      if(!isnull(version[1])) {
        report_simatic_version(vers:version[1], install:port + "/udp", concluded:sysdesc, port:port);
        exit(0);
      }
    }

  }

}

port = get_http_port(default:80);

url = '/Portal/Portal.mwsl?PriNav=Ident';
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL )continue;

if(egrep(pattern:"<title>.*SIMATIC.*1200.*</title>" , string: buf, icase: TRUE)) {

  vers = 'unknown';

  x = 0;
  lines = split(buf);

  foreach line (lines) {

    if("Firmware:" >< line) {
      version = eregmatch(pattern:">V.([^<]+)<", string:lines[x+1]);
      if(!isnull(version[1])) {
        vers = version[1];
        concluded = lines[x+1];
        break;
      }
    }

    x++;

  }

  install = '/';

  report_simatic_version(vers:vers,install:install,concluded:concluded,port:port);
  exit(0);

}

exit(0);
