# OpenVAS Vulnerability Test
# $Id: gnutella_export.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Misconfigured Gnutella
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Changes by rd: Description.
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11716");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Misconfigured Gnutella");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Remote file access");
  script_dependencies("find_service.nasl", "gnutella_detect.nasl");
  script_require_ports("Services/gnutella", 6346);

  script_tag(name:"solution", value:"Disable this Gnutella servent or configure it correctly.");

  script_tag(name:"summary", value:"The remote host is running the Gnutella servent service.

  It seems that the root directory of the remote host is visible through
  this service. Confidential files might be exported.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

function gnutella_read_data(socket, message) {

  local_var len, i, r2;
  len = 0;

  for (i = 22; i >= 19; i--)
    len = len * 256 + ord(message[i]);
  if (len > 0)
    r2 = recv(socket:socket, length:len);
  return r2;
}

function gnutella_search(socket, search) {

  local_var MsgId, Msg, r1, r2;

  MsgId = rand_str(length:16);
  Msg = raw_string( MsgId,               # Message ID
                    128,                 # Function ID
                    1,                   # TTL
                    0,                   # Hops taken
                    strlen(search)+3, 0,
                    0, 0,                # Data length (little endian)
                    0, 0,                # Minimum speed (LE)
                    search, 0);
  send(socket:socket, data:Msg);

  # We might get Ping and many other Gnutella-net messages
  # We just read and drop them, until we get our answer.
  while(1) {
    r1 = recv(socket:socket, length:23);
    if (strlen(r1) < 23)
      return;
    r2 = gnutella_read_data(socket:socket, message:r1);
    if (ord(r1[16]) == 129 && substr(r1, 0, 15) == MsgId)
      return r2;
  }
}

include("misc_func.inc");

port = get_kb_item("Services/gnutella");
if(! port)
  port = 6346;

if(! get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if(! soc)
  exit(0);

send(socket:soc, data:'GNUTELLA CONNECT/0.4\n\n');
r = recv(socket:soc, length:13);
if(r != 'GNUTELLA OK\n\n') {
  close(soc);
  exit(0);
}

# GTK-Gnutella sends a ping on connection
r = recv(socket:soc, length:23);
if (strlen(r) >= 23) {
  r2 = gnutella_read_data(socket:soc, message:r);
  if(ord(r[16]) == 0) { # Ping
    # Pong  (phony answer)
    MsgId = substr(r, 0, 15);
    ip = this_host();
    x = eregmatch(string: ip, pattern: "([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)");

    Msg = raw_string( MsgId,
                      1,                                          # pong
                      1,                                          # TTL
                      0,                                          # Hop
                      14, 0, 0, 0,
                      11, 11,                                     # Listening port
                      int(x[1]), int(x[2]), int(x[3]), int(x[4]), # IP
                      1, 1, 0, 0,                                 # File count (little endian)
                      1, 1, 0, 0);                                # KB count
    send(socket:soc, data:Msg);
  }
}

dangerous_file = make_list(
"boot.ini", "win.ini", "autoexec.bat",
"config.sys", "io.sys", "msdos.sys", "pagefile.sys",
"inetd.conf", "host.conf");

foreach d(dangerous_file) {
  r = gnutella_search(socket: soc, search: d);
  if(! isnull(r) && ord(r[0]) > 0) {
    close(soc);
    security_message(port:port);
    exit(0);
  }
}

close(soc);
exit(99);