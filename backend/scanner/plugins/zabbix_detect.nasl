###############################################################################
# OpenVAS Vulnerability Test
# $Id: zabbix_detect.nasl 9608 2018-04-25 13:33:05Z jschulte $
#
# ZABBIX Server/Agent Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100403");
  script_version("$Revision: 9608 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-25 15:33:05 +0200 (Wed, 25 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-12-17 19:46:08 +0100 (Thu, 17 Dec 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("ZABBIX Server/Agent Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service4.nasl");
  script_require_ports("Services/zabbix", 10050, 10051);

  script_tag(name:"summary", value:"Detection of a ZABBIX Server/Agent.

  The script sends a connection request to the server and attempts to
  identify the service from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

# https://www.zabbix.org/wiki/Docs/protocols/zabbix_agent/2.0#Active_agents
reqs = make_list( "ZBX_GET_HISTORY_LAST_ID", # Old agent request
                  '{"request":"active checks","host":"' + get_host_name() + '"}' ); # Zabbix is not responding on the above request on newer versions

ports = get_kb_list( "Services/zabbix" );
if( ! ports ) ports = make_list( 10050, 10051 );

foreach port( ports ) {

  if( ! get_port_state( port ) ) continue;

  foreach req( reqs ) {

    soc = open_sock_tcp( port );
    if( ! soc ) break;

    send( socket:soc, data:req );

    buf = recv( socket:soc, length:1024 );
    close( soc );
    if( isnull( buf ) ) continue;

    # examples for different versions (nb: There are non-ascii chars after ZBXD)
    # ZBXD       ZBX_NOTSUPPORTED Unsupported item key.
    # ZBXD       {"response":"failed","info":"host [192.168.56.99] not found"}
    # ZBXD       ZBX_NOTSUPPORTED
    # ZBXD       FAIL
    if( buf =~ "^ZBXD" ) {

      register_service( port:port, proto:"zabbix" );
      set_kb_item( name:"Zabbix/installed", value:TRUE );
      set_kb_item( name:"Zabbix/AgentServer/installed", value:TRUE );
      install = port + "/tcp";
      version = "unknown";
      cpe = "cpe:/a:zabbix:zabbix";

      register_product( cpe:cpe, location:install, port:port, service:"zabbix" );

      log_message( data:build_detection_report( app:"Zabbix Server/Agent",
                                                version:version,
                                                install:install,
                                                cpe:cpe,
                                                concluded:buf ),
                                                port:port );
      break; # break out of the "foreach req" and continue with the next port
    }
  }
}

exit( 0 );
