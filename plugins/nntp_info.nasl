###############################################################################
# OpenVAS Vulnerability Test
#
# Misc information on News server
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
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
###############################################################################

# NNTP protocol is defined by RFC 977
# NNTP message format is defined by RFC 1036 (obsoletes 850); see also RFC 822.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11033");
  script_version("2019-05-24T11:20:30+0000");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Misc information on News server");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("General");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/nntp", 119);

  script_add_preference(name:"From address : ", type:"entry", value:"OpenVAS <listme@listme.dsbl.org>");
  script_add_preference(name:"Test group name regex : ", type:"entry", value:"f[a-z]\.tests?");
  script_add_preference(name:"Max crosspost : ", type:"entry", value:"7");
  script_add_preference(name:"Local distribution", type:"checkbox", value:"yes");
  script_add_preference(name:"No archive", type:"checkbox", value:"no");

  script_tag(name:"solution", value:"Disable the server if it is not used");

  script_tag(name:"summary", value:"This script detects if the NNTP server is open to outside,
  counts the number of groups, and tries to post outside.

  This channel may been used by virus or trojan.");

  exit(0);
}

include('global_settings.inc');
include('network_func.inc');
include('nntp_func.inc');

user = get_kb_item("nntp/login");
pass = get_kb_item("nntp/password");
fromaddr = script_get_preference("From address : ");

# Michael Scheidell gave me this spam trap address.
if (! fromaddr)  { fromaddr="OpenVAS <listme@listme.dsbl.org>"; }

local_distrib = script_get_preference("Local distribution");
if (! local_distrib) local_distrib = "yes";
x_no_archive = script_get_preference("No archive");
if (!x_no_archive) x_no_archive = "no";
set_kb_item(name: "nntp/local_distrib", value: local_distrib);
set_kb_item(name: "nntp/x_no_archive", value: x_no_archive);


# WARNING! If the header X-OpenVAS is removed, change nntp_article function!
more_headers = strcat(
	'User-Agent: Mageni Security Scanner 2.2\r\n',
	'Organization: Mageni Security\r\n',
	'X-Scanner: Scanner can be found at http://www.mageni.net/\r\n',
	'X-Abuse-1: The machine at ', get_host_ip(),
	' was scanned from ', this_host(), '\r\n',
	"X-Abuse-2: If you [", get_host_ip(),
	"] are not currently running a security audit, please complain to them [",
	this_host(),
	'], not to Mageni\r\n',
	'X-Abuse-3: fields Path and NNTP-Posting-Host may give you more reliable information\r\n',
	'X-Abuse-4: Do not answer to the From address, it may be phony and you may blacklist your mail server\r\n',
	'X-NNTP-Posting-Host: ', this_host(), '\r\n'	);

if ("yes" >< local_distrib) { more_headers += 'Distribution: local\r\n';}
if ("yes" >< x_no_archive) { more_headers += 'X-No-Archive: yes\r\n';}

# tictac = time();
# if (tictac) more_headers = strcat(more_headers, "Date: ", tictac, '\r\n');

port = get_kb_item("Services/nntp");
if (!port) port = 119;
if(!get_port_state(port))exit(0);

s = open_sock_tcp(port);
if (!s) exit(0);

buff = recv_line(socket:s, length:2048);

ready=0; posting=0; noauth=1;
nolist=0;


if ("200 " >< buff) { ready=1; posting=1;}
if ("201 " >< buff) { ready=1;}
set_kb_item(name: "nntp/"+port+"/posting", value: posting);
set_kb_item(name: "nntp/"+port+"/ready", value: ready);

if (! ready) {
 # Not a NNTP server?
 close(s);
 exit(0);
}

notice = "";

# Does it need authentication before any command?

ng="NoSuchGroup" + string(rand());
send(socket: s, data: strcat('LIST ACTIVE ', ng, '\r\n'));
buff = recv_line(socket:s, length:2048);

if ("480 " >< buff) { noauth = 0; }

while (buff && buff != '.\r\n')
 buff = recv_line(socket:s, length:2048);

set_kb_item(name: "nntp/"+port+"/noauth", value: noauth);

authenticated = nntp_auth(socket:s, username: user, password: pass);

testgroups="";
testRE = script_get_preference("Test group name regex : ");
if (! testRE) { testRE = "f[a-z]\.tests?"; }
# Note: we hardcoded alt.test
testRE = "^(" + testRE + ") .*$";
max_crosspost = script_get_preference("Max crosspost : ");
if (! max_crosspost) { max_crosspost = 7; }

if (noauth)
notice += 'This NNTP server allows unauthenticated connections\n';

if (!noauth) {
 notice += 'This NNTP server does not allows unauthenticated connections\n';
 if (! authenticated)
  notice += 'As no good username/password was provided, we cannot send our test messages\n';
}

if (! posting) {
 notice += 'This NNTP server does not allow posting\n';
}

# No use to go on if we are unable to authenticate
if (! authenticated && ! noauth) {
 send(socket:s, data: 'QUIT\r\n');
 close(s);
 if (notice)
  log_message(port:port, data:notice);
 exit(0);
}

# Let's count the groups! (this is slow)

send(socket:s, data: 'LIST ACTIVE\r\n');
buff = recv_line(socket:s, length: 2048);

if (! ereg(pattern:"^2[0-9][0-9] ", string:buff)) { nolist=1; }

total_len = 8; nbg = 1;
testNGlist = "alt.test";

altNB=0; bizNB=0; compNB=0; miscNB=0;
newsNB=0; recNB=0; sciNB=0; socNB=0;
talkNB=0; humanitiesNB=0;

if (!nolist) {
 buff = recv_line(socket:s, length: 2048);
 n = 0;
 while (buff && ! ereg(pattern: '^\\.[\r\n]+$', string: buff))
 {
  if (ereg(pattern:"^alt\.", string: buff)) { altNB=altNB+1; }
  if (ereg(pattern:"^rec\.", string: buff)) { recNB=recNB+1; }
  if (ereg(pattern:"^biz\.", string: buff)) { bizNB=bizNB+1; }
  if (ereg(pattern:"^sci\.", string: buff)) { sciNB=sciNB+1; }
  if (ereg(pattern:"^soc\.", string: buff)) { socNB=socNB+1; }
  if (ereg(pattern:"^misc\.", string: buff)) { miscNB=miscNB+1; }
  if (ereg(pattern:"^news\.", string: buff)) { altNB=newsNB+1; }
  if (ereg(pattern:"^comp\.", string: buff)) { compNB=compNB+1; }
  if (ereg(pattern:"^talk\.", string: buff)) { talkNB=talkNB+1; }
  if (ereg(pattern:"^humanities\.", string: buff)) { humanitiesNB=humanitiesNB+1; }

  if (ereg(pattern:testRE, string: buff)) {
    group_name = ereg_replace(pattern:testRE, string:buff, icase:1, replace:"\1");
    # display(string("Group=", group_name, "\n"));
    l = strlen(group_name);
    if ((l + 1 + total_len <= 498) && (nbg < max_crosspost)) {
     total_len = total_len + l + 1;
     nbg = nbg + 1;
     testNGlist = string(testNGlist, ",", group_name);
    }
  }

  buff=recv_line(socket:s, length:2048);
  # display(string("> ", buff));
  n=n+1;
 }

 notice = string(notice,
		"For your information, we counted ",
		n,
		" newsgroups on this NNTP server:\n",
		altNB, " in the alt hierarchy, ",
		recNB, " in rec, ",
		bizNB, " in biz, ",
		sciNB, " in sci, ",
		socNB, " in soc, ",
		miscNB, " in misc, ",
		newsNB, " in news, ",
		compNB, " in comp, ",
		talkNB, " in talk, ",
		humanitiesNB, " in humanities.\n"
	);
}

if (nbg > 1) more_headers += 'Followup-To: alt.test\r\n';

if ("yes" >< local_distrib && is_private_addr())
 local_warning= 'This message should not appear on a public news server.\r\n';
else
 local_warning = '\r\n';


msgid = nntp_make_id(str: "post");
# display(string("testNGlist=", testNGlist, "\n"));

msg = strcat(
	"Newsgroups: ", testNGlist, '\r\n',
	"Subject: Scanner post test ", rand(), ' (ignore)\r\n',
	"From: ", fromaddr, '\r\n',
	"Message-ID: ", msgid, '\r\n',
	more_headers,
	'Content-Type: text/plain; charset: us-ascii\r\n',
	'Lines: 2\r\n',
	'\r\n',
	'Test message (post). Please ignore.\r\n',
	local_warning, '.\r\n');

posted = nntp_post(socket: s, message: msg);
if (posted == -1)
log_message(port: port,
data: "The server rejected the message. Try again without 'local distribution'
if you don't mind leaking information outside");


send(socket:s, data: 'QUIT\r\n');
close(s);

#

sent = 0;
if (nntp_article(id: msgid, timeout: 10, port: port, username: user, password:pass)) { sent = 1; posted=1; i=9999; }

# Remember that this might be (-1)
set_kb_item(name: "nntp/"+port+"/posted", value: posted);

if (posted && ! posting) {
 notice=notice+"Although this server says it does not allow posting, we could send a message";
 if (! sent) notice = notice + ". We were unable to read it again, though...";
 notice += '\n';
}

if (! posted && posting)
 notice = string(notice, "Although this server says it allows posting, we were unable to send a message\n(posted in ",testNGlist, ")\n");

if (posting && posted && ! sent)
  notice += 'Although this server accepted our test message for delivery, we were unable to read it again\n';

if (! sent) {
  if (notice)
    log_message(port: port, data: notice);
  exit(0);
}

# Test Supersede

supid = nntp_make_id(str: "super");
posted = 0; sent = 0; superseded = 0;

sup = strcat(
	"Supersedes: ", msgid, '\r\n',
	"Newsgroups: ", testNGlist, '\r\n',
	"Subject: Supersede test ", rand(), ' (ignore)\r\n',
	"From: ", fromaddr, '\r\n',
	"Message-ID: ", supid, '\r\n',
	more_headers,
	'Content-Type: text/plain; charset: us-ascii\r\n',
	'Lines: 2\r\n',
	'\r\n',
	'Test message (supersede). Please ignore.\r\n',
	local_warning, '.\r\n');

s = nntp_connect(port:port, username: user, password: pass);
if (s) {
 posted = nntp_post(socket: s, message: sup);
 send(socket:s, data: 'QUIT\r\n');
 close(s);
}

if (nntp_article(id: supid, timeout: 10, username: user, password:pass)) { sent=1; posted=1; }
if (! nntp_article(id: msgid, timeout: 10, username: user, password:pass)) { superseded = 1; }

if (superseded)
  notice += 'This NNTP server implements Supersede\n';

if (!superseded && posted)
  notice += 'This NNTP server does not implement Supersede\n';

if (!superseded && !posted)
  notice += 'We were unable to Supersede our test article\n';

set_kb_item(name: "nntp/"+port+"/supersede", value: superseded);

# Test cancel

if (superseded) { msgid = supid; }

canid = nntp_make_id(str:"cancel");

can = strcat(
	"Newsgroups: ", testNGlist, '\r\n',
	"Subject: cmsg cancel ", msgid, '\r\n',
	"From: ", fromaddr, '\r\n',
	"Message-ID: ", canid, '\r\n',
	"Control: cancel ", msgid, '\r\n',
	more_headers,
	'Content-Type: text/plain; charset: us-ascii\r\n',
	'Lines: 2\r\n',
	'\r\n',
	'Test message (cancel). Please ignore.\r\n',
	local_warning, '.\r\n');

s = nntp_connect(port:port, username: user, password: pass);
if (s) {
 posted = nntp_post(socket: s, message: can);
 send(socket:s, data: 'QUIT\r\n');
 close(s);
}

cancel = 0;
if (! nntp_article(id: msgid, timeout: 10, username: user, password:pass)) { cancel = 1; }

if (! cancel)
  notice += 'We were unable to Cancel our test article\n';
set_kb_item(name: "nntp/"+port+"/cancel", value: cancel);

if (notice)
  log_message(port: port, data: notice);
