###############################################################################
# OpenVAS Vulnerability Test
#
# SAP Message Server Service Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.141067");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-09 09:04:58 +0700 (Wed, 09 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SAP Message Server Service Detection");

  script_tag(name:"summary", value:"A SAP Message Server Service is running at this host.

SAP Message Server is for

  - Central communication channel between the individual application servers (instances) of the system

  - Load distribution of logons using SAP GUI and RFC with logon groups

  - Information point for the Web Dispatcher and the application servers");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 3600, 3900);

  script_xref(name:"URL", value:"https://www.sap.com/");

  exit(0);
}

include("host_details.inc");
include("dump.inc");
include("misc_func.inc");

# Basic request from https://www.coresecurity.com/content/SAP-netweaver-msg-srv-multiple-vulnerabilities
# See as well pysap for further information

port = get_unknown_port(default: 3900);

# Message Server runs on ports 36xx or 39xx
if (port < 3600 || port >= 3700)
  if (port < 3900 || port >= 4000)
    exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

client = '-' + crap(data: ' ', length: 39);

query = raw_string(0x00, 0x00, 0x00, 0x6e,		# message length
                   '**MESSAGE**', 0x00,
                   0x04,				# version
                   0x00,				# errorno
                   client,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	# msgtype/reserved/key
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x08,				# flag / iflag (MS_LOGIN_2)
                   client,
                   0x00, 0x00);				# padding

send(socket: soc, data: query);
recv = recv(socket: soc, length: 512);

if (!recv || strlen(recv) < 111 || substr(recv, 4, 14) != '**MESSAGE**') {
  close(soc);
  exit(0);
}

set_kb_item(name: "sap_message_server/detected", value: TRUE);

register_service(port: port, ipproto: "tcp", proto: "sap_msg_service");

server = substr(recv, 72, 111);
server_name = bin2string(ddata: server, noprint_replacement: '');

# nb: This tries to dump some general information (this succeeds just if we have permission to do so)
query = raw_string(0x00, 0x00, 0x00, 0xa2,		# message length
                   '**MESSAGE**', 0x00,
                   0x04,				# version
                   0x00,				# errorno
                   server,				# to name
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	# msgtype/reserved/key
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x02, 0x01,				# flag / iflag (MS_REQUEST / MS_SEND_NAME)
                   client,				# from name
                   0x00, 0x00,				# padding
                   0x1e,				# opcode (MS_DUMP_INFO)
                   0x00, 0x01, 0x03,			# opcode_error, opcode_version, opcode_charset
                   0x02,				# dump_dest
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	# dump_filler, dump_index
                   0x03,				# dump_command (MS_DUMP_PARAMS)
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # dump name (empty)
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00);

send(socket: soc, data: query);
recv = recv(socket: soc, length: 2048);
close(soc);

if (recv && strlen(recv) > 119)
  info = substr(recv, 119);

report = 'A SAP Message Server service is running at this port.\n\nThe following server name was extracted:\n\n' +
         'Server Name:     ' + server_name + '\n';

if (info)
  report += '\nAdditional obtained info:\n\n' + info;

log_message(port: port, data: report);

exit(0);