# OpenVAS Vulnerability Test
# $Id: check_smtp_helo.nasl 6046 2017-04-28 09:02:54Z teissa $
# Description: SMTP server accepts us
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

tag_summary = "This script does not perform any security test.
It verifies that OpenVAS that connect to the remote SMTP
server and that it can send a HELO request.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300001");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 6046 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");

 script_name("SMTP server accepts us");
		 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
 script_family("SMTP problems");
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");

 script_dependencies("find_service_3digits.nasl");
 script_require_ports("Services/smtp", 25);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
include('global_settings.inc');
include('misc_func.inc');
include('smtp_func.inc');

port = get_kb_item("Services/smtp");
if (! port) port = 25;
if (! get_port_state(port)) exit(0);

# Some broken servers return _two_ code lines for one query!
# Maybe this function should be put in smtp_func.inc?
function smtp_recv(socket, retry)
{
 local_var r, r2, i, l;
 for (i = 0; i < 6; i ++)
 {
  r = recv(socket: socket, length: 4096);
  l = strlen(r);
  if (l == 0 && retry -- <= 0) return r2;
  r2 += r;
  if (l >= 2 && substr(r, l-2) == '\r\n') return r2;
 }
 return r2;
}

s = open_sock_tcp(port);

if (! s)
{
 debug_print('Cannot open connection to port ', port, '\n');
 set_kb_item(name: 'smtp/'+port+'/broken', value: TRUE);
 set_kb_item(name: 'SMTP/'+port+'/broken', value: TRUE);
 if (port == 25)
  set_kb_item(name: 'SMTP/wrapped', value: TRUE);
 exit(0);
}

r = smtp_recv(socket: s, retry: 3);
if (! r)
{
 debug_print('No SMTP welcome banner on port ', port, '\n');
 close(s);
 set_kb_item(name: 'smtp/'+port+'/broken', value: TRUE);
 set_kb_item(name: 'SMTP/'+port+'/broken', value: TRUE);
 if (port == 25)
  set_kb_item(name: 'SMTP/wrapped', value: TRUE);
 exit(0);
}

if (r =~ '^4[0-9][0-9][ -]')
{
 debug_print('SMTP on port ', port, ' is temporarily closed: ', r);
 log_message(port: port, data: strcat(
"The SMTP server on this port answered with a ", substr(r, 0, 2), " code.
This means that it is temporarily unavailable because it is
overloaded or any other reason.

** OpenVAS tests will be incomplete. You should fix your MTA and
** rerun OpenVAS, or disable this server if you don't use it.
"));
 close(s);
 set_kb_item(name:'smtp/'+port+'/temp_denied', value: TRUE);
 exit(0);
}

if (r =~ '^5[0-9][0-9][ -]')
{
 debug_print('SMTP on port ', port, ' is permanently closed: ', r);
 log_message(port: port, data: strcat(
"The SMTP server on this port answered with a ", substr(r, 0, 2), " code.
This means that it is permanently unavailable because the OpenVAS
server IP is not authorized, blacklisted or any other reason.

** OpenVAS tests will be incomplete. You may try to scan your MTA
** from an authorized IP or disable this server if you don't use it.
"));
 set_kb_item(name: 'smtp/'+port+'/denied', value: TRUE);
 close(s);
 exit(0);
}

heloname = 'example.com';
send(socket: s, data: 'HELO '+heloname+'\r\n');
r = smtp_recv(socket: s, retry: 3);
if (r =~ '^[45][0-9][0-9][ -]')
{
 debug_print('SMTP server on port ', port, ' answers to HELO(', heloname, '): ', r);
 heloname = this_host_name();
 if (! heloname) heloname = this_host();
 send(socket: s, data: 'HELO '+heloname+'\r\n');
 r = smtp_recv(socket: s, retry: 3);
 if (strlen(r) == 0)	# Broken connection ?
 {
  close(s);
  sleep(1);	# Try to avoid auto-blacklist
  s = open_sock_tcp(port);
  if (s)
  {
   send(socket: s, data: 'HELO '+heloname+'\r\n');
   r = smtp_recv(socket: s, retry: 3);
  }
 } 
 debug_print('SMTP server on port ', port, ' answers to HELO(', heloname, '): ', r);
}

debug_print(level: 2, 'SMTP server on port ', port, ' answers to HELO: ', r);

send(socket: s, data: 'QUIT\r\n');
close(s);

if (r !~ '^2[0-9][0-9][ -]')
{
 if (strlen(r) >= 3)
  report = strcat(
"The SMTP server on this port answered with a ", substr(r, 0, 2), " code
to HELO requests.");
 else
  report = "The SMTP server on this port rejects our HELO requests.";
 report += "
This means that it is unavailable because the scanner IP is not
authorized or blacklisted, or that the hostname is not consistent
with the IP.

** Scanner tests will be incomplete. You may try to scan your MTA
** from an authorized IP or fix the Scanner hostname and rescan this server.
";
 
 log_message(port: port, data: report);
 set_kb_item(name: 'smtp/'+port+'/denied', value: TRUE);
}
else
{
 set_kb_item(name: 'smtp/'+port+'/helo', value: heloname);
}
