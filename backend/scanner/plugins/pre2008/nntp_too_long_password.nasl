# OpenVAS Vulnerability Test
# $Id: nntp_too_long_password.nasl 14336 2019-03-19 14:53:10Z mmartin $
# Description: NNTP password overflow
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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

# Overflow on the user name is tested by cassandra_nntp_dos.nasl
#
# NNTP protocol is defined by RFC 977
# NNTP message format is defined by RFC 1036 (obsoletes 850); see also RFC 822.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17229");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("NNTP password overflow");

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("find_service_3digits.nasl", "nntp_info.nasl");
  script_require_ports("Services/nntp", 119);
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Apply the latest patches from your vendor or
	 use a safer software.");
  script_tag(name:"summary", value:"OpenVAS was able to crash the remote NNTP server by sending
  a too long password. This flaw is probably a buffer overflow and might be exploitable to
  run arbitrary code on this machine.");
  exit(0);
}

#
include('global_settings.inc');
include('nntp_func.inc');

port = get_kb_item("Services/nntp");
if(!port) port = 119;
if(! get_port_state(port)) exit(0);

user = get_kb_item("nntp/login");
# pass = get_kb_item("nntp/password");

ready = get_kb_item("nntp/"+port+"/ready");
if (! ready) exit(0);

# noauth = get_kb_item("nntp/"+port+"/noauth");
# posting = get_kb_item("nntp/"+port+"/posting");

s = open_sock_tcp(port);
if(! s) exit(0);

line = recv_line(socket: s, length: 2048);

if (! user) user = "openvas";

send(socket:s, data: strcat('AUTHINFO USER ', user, '\r\n'));
buff = recv_line(socket:s, length:2048);
send(socket:s, data: strcat(crap(22222), '\r\n'));
buff = recv_line(socket:s, length:2048);
close(s);
sleep(1);

s = open_sock_tcp(port);
if(! s)
{
  security_message(port);
  exit(0);
}
else
 close(s);

if (! buff)
security_message(port: port, data:
"The remote NNTP daemon abruptly closes the connection
when it receives a too long password.
It might be vulnerable to an exploitable buffer overflow;
so a cracker might run arbitrary code on this machine.

*** Note that Scanner did not crash the service, so this
*** might be a false positive.
*** However, if the NNTP service is run through inetd
*** it is impossible to reliably test this kind of flaw.

Solution: apply the latest patches from your vendor,
	 or a safer software.");


