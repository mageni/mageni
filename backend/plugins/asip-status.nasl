# OpenVAS Vulnerability Test
# $Id: asip-status.nasl 13541 2019-02-08 13:21:52Z cfischer $
# Description: AppleShare IP Server status query
#
# Authors:
# James W. Abendschan <jwa@jammed.com>
#
# Copyright:
# Copyright (C) 2005 James W. Abendschan <jwa@jammed.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

# NASL script to send a DSIGetStatus / FPGetSrvrInfo to an AppleShare IP
# server & parse the reply
# based off of http://www.jammed.com/~jwa/hacks/security/asip/asip-status

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10666");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("AppleShare IP / Apple Filing Protocol (AFP) Service Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2005 James W. Abendschan <jwa@jammed.com>");
  script_dependencies("find_service.nasl");
  script_require_ports(548);

  script_tag(name:"summary", value:"The remote host is running an AppleShare IP / Apple Filing Protocol (AFP)
  service.

  By sending a DSIGetStatus request on tcp port 548, it was possible to disclose information about the remote host.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

function b2dw(a, b, c, d) {

  local_var a, b, c, d;
  local_var a1, b1, c1, dword;

  a1 = a * 256 * 256 * 256;
  b1 = b * 256 * 256;
  c1 = c * 256;
  dword = a1 + b1 + c1 + d;
  return(dword);
}

function b2w(low, high) {

  local_var low, high;
  local_var word;

  word = high * 256;
  word = word + low;
  return(word);
}

# return a pascal string
function pstring(offset, packet) {

  local_var offset, packet;
  local_var plen, i, pstr;

  plen = ord(packet[offset]);
  pstr = ""; # avoid interpreter warning
  for (i=1;i<plen+1;i=i+1) {
    pstr = pstr + packet[offset+i];
  }
  return(pstr);
}

# pull out counted pstrings in packet starting at offset
function pluck_counted(offset, packet) {

  local_var offset, packet;
  local_var count, str, plucked, count_offset, j;

  count = ord(packet[offset]);
  str = "";
  plucked = "";
  count_offset = offset + 1;
  for (j=0;j<count;j=j+1) {
    str = pstring(offset:count_offset, packet:packet);
    # offset + length of data + length byte
    count_offset = count_offset + strlen(str) + 1;
    plucked += str;
    # lame coz there's no != ?
    if (j < count-1)
      plucked += "/";
  }
  return(plucked);
}

# parse FPGetSrvrInfo reply (starting at DSIGetRequest reply packet + 16)
function parse_FPGetSrvrInfo(packet, port) {

  local_var packet, port;
  local_var machinetype_offset, machinetype, afpversioncount_offset, versions;
  local_var uamcount_offset, uams, servername, report;

  machinetype_offset = b2w(low:ord(packet[17]), high:ord(packet[16])) + 16;
  machinetype = pstring(offset:machinetype_offset, packet:packet);

  afpversioncount_offset = b2w(low:ord(packet[19]), high:ord(packet[18])) + 16;
  versions = pluck_counted(offset:afpversioncount_offset, packet:packet);

  uamcount_offset = b2w(low:ord(packet[21]), high:ord(packet[20])) + 16;
  uams = pluck_counted(offset:uamcount_offset, packet:packet);

  servername = pstring(offset:26, packet:packet);

  report = string("This host is running an AppleShare IP / Apple Filing Protocol (AFP) service.\n\n",
                  "Machine type: ", machinetype, "\n",
                  "Server name:  ", servername, "\n",
                  "UAMs:         ", uams, "\n",
                  "AFP Versions: ", versions, "\n");

  if ("No User Authen" >< uams) {
    report += '\nThe remote service allows the "guest" user to connect.';
  }

  if ("Cleartxt Passwrd" >< uams) {
    report += '\nThe remote service allows "Cleartext" connections.';
    set_kb_item(name:"asip_afp/" + port + "/iscleartext", value:TRUE);
    set_kb_item(name:"asip_afp/iscleartext", value:TRUE);
  }

  log_message(port:port, data:report);
  register_service(port:port, proto:"appleshare");

  if(machinetype) {
    set_kb_item(name:"asip_afp/" + port + "/banner", value:machinetype);
    set_kb_item(name:"asip_afp/banner/available", value:TRUE);
  }

  if(uams) {
    set_kb_item(name:"asip_afp/" + port + "/uams", value:uams);
    set_kb_item(name:"asip_afp/uams/available", value:TRUE);
  }

  if(servername) {
    set_kb_item(name:"asip_afp/" + port + "/servername", value:servername);
    set_kb_item(name:"asip_afp/servername/available", value:TRUE);

    if(defined_func("resolve_host_name") && # Added for master / GVM-10 in commit 2a9920b82a6cd7793cd7f36f5cacd68f2eff6234
       defined_func("add_host_name")) { # Available since GVM-10 / git commit cf2ed60
      if(resolve_host_name(hostname:servername))
        add_host_name(hostname:servername, source:"AppleShare IP / Apple Filing Protocol (AFP) Service");
    }
  }
}

# parse ASIP reply packet
function parse_DSIGetStatus(packet, port) {

  local_var packet, port;
  local_var flags, cmd, reqidL, reqidH, reqid, edo, datalen, reserved;

  flags = ord(packet[0]);
  cmd = ord(packet[1]);
  reqidL = ord(packet[2]);
  reqidH = ord(packet[3]);

  reqid = b2w(low:reqidL, high:reqidH);

  if (!(reqid == 57005)) {
    exit(0);
  }

  # ignore error / data offset DO for now
  edo = b2dw(a:ord(packet[4]), b:ord(packet[5]), c:ord(packet[6]), d:ord(packet[7]));

  datalen = b2dw(a:ord(packet[8]), b:ord(packet[9]), c:ord(packet[10]), d:ord(packet[11]));

  reserved = b2dw(a:ord(packet[12]), b:ord(packet[13]), c:ord(packet[14]), d:ord(packet[15]));

  if (!(cmd == 3)) {
    exit(0);
  }

  return(parse_FPGetSrvrInfo(packet:packet, port:port));
}

# send the DSIGetStatus packet
function send_DSIGetStatus(sock) {

  local_var sock;
  local_var packet, buf;

  packet = raw_string(
                      0x00,                   # 0- request, 1-reply
                      0x03,                   # 3- DSIGetStatus
                      0xad, 0xde, 0x00,       # request ID
                      0x00, 0x00, 0x00, 0x00, # data field
                      0x00, 0x00, 0x00, 0x00, # length of data stream header
                      0x00, 0x00, 0x00, 0x00  # reserved
                     );

  send(socket:sock, data:packet);
  buf = recv(socket:sock, length:8192, timeout:30);
  if (strlen(buf) == 0) {
    exit(0);
  }
  return(buf);
}

function asip_status(port) {

  local_var port;
  local_var s, packet;

  s = open_sock_tcp(port);
  if (s) {
    packet = send_DSIGetStatus(sock:s);
    if(strlen(packet) > 17) {
      parse_DSIGetStatus(packet:packet, port:port);
    }
    close(s);
  }
}

port = 548;
if(service_is_unknown(port:port) && get_port_state(port)){
  asip_status(port:port);
}