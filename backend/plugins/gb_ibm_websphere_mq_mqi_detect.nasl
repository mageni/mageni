###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_mq_mqi_detect.nasl 12910 2018-12-30 21:51:49Z cfischer $
#
# IBM WebSphere MQ Detection (MQI)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141712");
  script_version("$Revision: 12910 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-30 22:51:49 +0100 (Sun, 30 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-11-23 10:29:03 +0700 (Fri, 23 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM WebSphere MQ Detection (MQI)");

  script_tag(name:"summary", value:"Detection of IBM WebSphere MQ.

The script sends a MQI request to the server and attempts to detect IBM WebSphere MQ and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 1414, 1415);

  script_xref(name:"URL", value:"https://www.ibm.com/products/mq");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

# Based on https://github.com/rapid7/metasploit-framework/pull/10876 and
# https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-mq.c
# https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-mq.h

port = get_unknown_port(default: 1414);

capabilities = make_list(raw_string(0x26),	# MQ Request, Split messages, conversation capable
                         raw_string(0x07),
                         raw_string(0x08));

function create_init_packet(socket, capabilities) {
  local_var socket, capabilities, req, channel_name, qm_name;

  channel_name = "SYSTEM.DEF.SVRCONN  ";	# Seems to be a default channel (20 byte)
  qm_name      = "QM1";				# Queue Manager Name

  req = raw_string(0x54, 0x53, 0x48, 0x20,	# Struct ID (Transmission Segment Header (TSH))
                   0x00, 0x00, 0x01, 0x0c,	# MQSegLen
                   0x02,			# ByteOrder (little endian)
                   0x01,			# Segment Type (INITIAL_DATA)
                   0x01,			# Ctl Flag 1
                   0x00,			# Ctl Flag 2
                   0x00, 0x00, 0x00, 0x00,	# LUW Ident
                   0x00, 0x00, 0x00, 0x00,
                   0x22, 0x02, 0x00, 0x00,	# Encoding (FLT_IEEE_REVERSED/DEC_REVERSED/INT_REVERSED)
                   0xb5, 0x01,			# CCSID
                   0x00, 0x00,			# Reserved

                   0x49, 0x44, 0x20, 0x20,	# Struct ID (ID)
                   0x0d,			# FAP level
                   capabilities,
                   0x00,			# ECapFlag1
                   0x00,			# IniErrFlag1
                   0x00, 0x00,			# Reserved
                   0x32, 0x00,			# MaxMsgBtch
                   0xec, 0x7f, 0x00, 0x00,      # MaxTrSize
                   0x00, 0x00, 0x40, 0x00,      # MaxMsgSize
                   0xff, 0xc9, 0x9a, 0x3b,	# SeqWrapVal
                   channel_name,
                   0x87,			# CapFlag2
                   0x00,			# ECapFlag2
                   0x5b, 0x01,			# ccsid
                   qm_name + crap(data: ' ', length: 45),
                   0x2c, 0x01, 0x00, 0x00,	# HBInterval
                   0x8a, 0x00,			# EFLLength
                   0x00,			# IniErrFlg2
                   0x55,			# Reserved
                   0x00, 0xff,			# HdrCprsLst
                   0x00, 0xff, 0xff, 0xff,	# MsgCprsLst
                   0xff, 0xff, 0xff, 0xff,
                   0xff, 0xff, 0xff, 0xff,
                   0xff, 0xff, 0xff, 0xff,
                   0x00, 0x00,			# Reserved
                   0x00, 0x00, 0x00, 0x00,	# SSLKeyRst
                   0x00, 0x00, 0x00, 0x00,	# ConvBySkt
                   0x05,			# CapFlag3
                   0x00,			# ECapFlag3
                   0x00, 0x00,			# Reserved
                   0x10, 0x13, 0x00, 0x00,	# ProcessId
                   0x01, 0x00, 0x00, 0x00,	# ThreadId
                   0x01, 0x00, 0x00, 0x00,	# TraceId
                   'MQMM09000000',		# ProdId
                   'MQMID' + crap(data: ' ', length: 43),	# MQM ID
                   0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,	# PAL
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		# R
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                   );

  return req;
}

sock = open_sock_tcp(port);
if (!sock)
  exit(0);

version = "unknown";

for (i=0; i<3; i++) {
  packet = create_init_packet(capabilities: capabilities[i]);

  send(socket: sock, data: packet);
  recv = recv(socket: sock, length: 2048);

  if (!recv && !found) {
    close(sock);
    exit(0);
  }
  # Maybe detected but further requests get rejected
  else if (!recv && found) {
    break;
  }

  if (hexstr(substr(recv, 0, 3)) != "54534820") {
    close(sock);
    exit(0);
  }

  found = TRUE;

  len = strlen(recv);
  errcode = substr(recv, len-4);

  # Wrong channel type or SSL required
  if (hexstr(errcode) == "02000000" || hexstr(errcode) == "18000000")
    continue;

  if (strlen(recv) > 187) {
    qm_name = substr(recv, 76, 123);
    extra += 'QM Name:   ' + chomp(qm_name);

    version = "";

    # e.g. MQMM09010000
    vers = substr(recv, 180, 187);
    for (i=0; i<strlen(vers); i+=2) {
      if (vers[i] == "0")
        version += vers[i+1];
      else
        version += vers[i] + vers[i+1];

      if (i+2 < strlen(vers))
        version += '.';
    }
    break;
  }
}

close(sock);

if (found) {
  set_kb_item(name: "ibm_websphere_mq/detected", value: TRUE);
  set_kb_item(name: "ibm_websphere_mq/mqi/port", value: port);

  register_service(port: port, proto: "websphere_mq", message: "A WebSphere MQ service answering to MQI requests seems to be running on this port.");
  log_message(port: port, data: "A WebSphere MQ service answering to MQI requests seems to be running on this port.");

  if (version != "unknown")
    set_kb_item(name: "ibm_websphere_mq/mqi/" + port + "/version", value: version);
}

exit(0);