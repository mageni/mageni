###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sap_diag_service_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# SAP DIAG Service Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141088");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-05-22 14:33:46 +0700 (Tue, 22 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SAP DIAG Service Detection");

  script_tag(name:"summary", value:"A SAP DIAG (Dynamic Information and Action Gateway) Service is running at
this host.

DIAG is a propretiary communication protocol between the SAP GUI and the SAP application server.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 3200);

  script_xref(name:"URL", value:"https://www.sap.com/");

  exit(0);
}

include("host_details.inc");
include("dump.inc");
include("byte_func.inc");
include("misc_func.inc");

# From pysap examples
# Wireshark DIAG dissector https://github.com/CoreSecurity/SAP-Dissection-plug-in-for-Wireshark

port = get_unknown_port(default: 3200);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

init_query = raw_string(# SAP NI Protocol
                        0x00, 0x00, 0x01, 0x06,			# Length
                        # SAP DIAG Protocol
                        #   # DP Header
                        0xff, 0xff, 0xff, 0xff,			# Request ID
                        0x0a,					# Retcode
                        0x00,					# Sender ID
                        0x00,					# Action Type
                        0x00, 0x00, 0x00, 0x00,			# Request Info
                        0xff, 0xff, 0xff, 0xff,			# TID
                        0xff, 0xff,				# UID
                        0xff,					# Mode
                        0xff, 0xff, 0xff, 0xff,			# WP Id
                        0xff, 0xff, 0xff, 0xff,			# WP Ca Blk
                        0xff, 0xff, 0xff, 0xff,			# APPC Ca Blk
                        0x3e, 0x00, 0x00, 0x00,			# Len
                        0x00,					# New Stat: NO_CHANGE
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,	# Request ID
                        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                        0x20, 0x20, 0x20, 0x20, 0x20,
                        0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30,  # Terminal (127.0.0.1, but could be random)
                        0x2e, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x20, 0x20, 0x20, 0x20,
                        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                        0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        #   # Header
                        0x00,					# Mode 0
                        0x01,					# Com Flag
                        0x00,					# Mode Stat
                        0x00,					# Error Number
                        0x00,                                   # Message Type
                        0x00,                                   # Message Info
                        0x00,					# Message Rc
                        0x00,                                   # Compression (no compression)
                        #   # Message
                        #      # Item
                        0x10,					# APPL
                        0x04,					# ID: ST_USER
                        0x02,					# SID: CONNECT
                        0x00, 0x0c,                             # Length
                        #      # Value
                        0x00, 0x00, 0x00, 0xc8,			# Protocol Version
                        0x00, 0x00, 0x04, 0x4c,			# Code Page
                        0x00, 0x00, 0x13, 0x89,			# WS Type
                        #      # Item
                        0x10,					# APPL
                        0x04,					# ID: ST_USER
                        0x0b,                                   # SID: SUPPORTDATA
                        0x00, 0x20,				# Length
                        #      # Value
                        0xff, 0x7f, 0xfe, 0x2d, 0xda, 0xb7, 0x37,  # Different flags
                        0xd6, 0x74, 0x08, 0x7e, 0x13, 0x05, 0x97,
                        0x15, 0x97, 0xef, 0xf2, 0x3f, 0x8d, 0x07,
                        0x70, 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00);

send(socket: soc, data: init_query);

recv = recv(socket: soc, length: 4);
if (strlen(recv) != 4) {
  close(soc);
  exit(0);
}
len = getdword(blob: recv);

# Receive the whole response
recv = recv(socket: soc, length: len);
close(soc);

if ("UnicodeLittleUnmarked" >!< recv)
  exit(0);

set_kb_item(name: "sap_diag_protocol/detected", value: TRUE);

register_service(port: port, proto: "sap_diag");

# Parse through the message
for (i = 0; i < len; i++) {
  # DBNAME
  # eg. DEV
  if ((hexstr(recv[i]) == "10") && (hexstr(recv[i+1]) == "06") && (hexstr(recv[i+2]) == "02")) {
    dblen = getword(blob: recv, pos: i+3);
    dbname = substr(recv, i+5, i+5+dblen-1);
    i += 5+dblen;
  }

  # CPUNAME
  # eg. SERVER2
  if ((hexstr(recv[i]) == "10") && (hexstr(recv[i+1]) == "06") && (hexstr(recv[i+2]) == "03")) {
    cpulen = getword(blob: recv, pos: i+3);
    cpuname = substr(recv, i+5, i+5+cpulen-1);
    i += 5+cpulen;
  }

  # KERNEL_VERSION
  # eg. 731.7200.515
  if ((hexstr(recv[i]) == "10") && (hexstr(recv[i+1]) == "06") && (hexstr(recv[i+2]) == "29")) {
    kernellen = getword(blob: recv, pos: i+3);
    kernelver = bin2string(ddata: substr(recv, i+5, i+5+kernellen-2), noprint_replacement: '.');
    i += 5+kernellen;
  }

  # DIAGVERSION
  # eg. 200
  if ((hexstr(recv[i]) == "10") && (hexstr(recv[i+1]) == "06") && (hexstr(recv[i+2]) == "06")) {
    diaglen = getword(blob: recv, pos: i+3);
    # currently this should be a word long
    if (diaglen == 2)
      diagver = getword(blob: recv, pos: i+5);
    i += 5+diaglen;
  }

  # SESSION_ICON
  # eg. SAP R/3 (1) ECD
  if ((hexstr(recv[i]) == "10") && (hexstr(recv[i+1]) == "0c") && (hexstr(recv[i+2]) == "0a")) {
    icolen = getword(blob: recv, pos: i+3);
    sess_icon = substr(recv, i+5, i+5+icolen-1);
    i += 5+icolen;
  }

  # SESSION_TITLE
  # eg. SAP
  if ((hexstr(recv[i]) == "10") && (hexstr(recv[i+1]) == "0c") && (hexstr(recv[i+2]) == "09")) {
    titlelen = getword(blob: recv, pos: i+3);
    sess_title = substr(recv, i+5, i+5+titlelen-1);
    i += 5+titlelen;
  }
}

report = 'A SAP DIAG service is running at this port.';

if (dbname || cpuname) {
  report += '\n\nThe following information was extracted:\n\n';
  if (dbname)
    report += 'DBNAME:          ' + dbname + '\n';
  if (cpuname)
    report += 'CPUNAME:         ' + cpuname + '\n';
  if (kernelver)
    report += 'KERNEL_VERSION:  ' + kernelver + '\n';
  if (diagver)
    report += 'DIAGVERSION:     ' + diagver + '\n';
  if (sess_icon)
    report += 'SESSION_ICON:    ' + sess_icon + '\n';
  if (sess_title)
    report += 'SESSION_TITLE:   ' + sess_title + '\n';
}

log_message(port: port, data: report);

exit(0);
