# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108546");
  script_version("$Revision: 13959 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 12:27:26 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-02-09 16:58:00 +0100 (Sat, 09 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OSSEC/Wazuh ossec-authd Service Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service6.nasl");
  script_require_ports("Services/unknown", 1515);

  script_xref(name:"URL", value:"https://www.ossec.net/");

  script_tag(name:"summary", value:"This script tries to detect an installed OSSEC/Wazuh ossec-authd service
  on the remote host.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

port = get_unknown_port( default:1515 );
soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

# https://github.com/wazuh/wazuh/blob/5e71e413f6dc549e68dbc2bc16793c62d314cada/src/os_auth/main-client.c#L371-L417
# https://github.com/ossec/ossec-hids/blob/dd93bb0f1f2a58b9fcb19a22db4859b973a5277c/src/os_auth/main-client.c#L314-L329
req = "OSSEC A:'" + this_host_name() + "'" + '\n';
send( socket:soc, data:req );
buf = recv_line( socket:soc, length:512 );
close( soc );

# Examples:
# OSSEC K:'025 myhostname myip agentkey'
# -> https://github.com/wazuh/wazuh/blob/5e71e413f6dc549e68dbc2bc16793c62d314cada/src/os_auth/main-server.c#L1107
# OSSEC K:'agentkey'
# -> https://github.com/ossec/ossec-hids/blob/3951139adbdb33126de684f9172cc5b017f2f4f0/src/os_auth/main-server.c#L522
#
# nb: If password auth is enabled or the client needs to provide a valid cert we're not getting a response from the service.

if( ! buf || ( buf !~ "^OSSEC K:'.+'" && "ERROR: Unable to add agent." >!< buf ) )
  exit( 0 );

register_service( port:port, proto:"ossec-authd" );
set_kb_item( name:"ossec_wazuh/authd/detected", value:TRUE );
set_kb_item( name:"ossec_wazuh/authd/no_auth", value:TRUE );
set_kb_item( name:"ossec_wazuh/authd/" + port + "/detected", value:TRUE );
set_kb_item( name:"ossec_wazuh/authd/" + port + "/no_auth", value:TRUE );

log_message( port:port, data:"An ossec-authd service seems to be running on this port." );
exit( 0 );