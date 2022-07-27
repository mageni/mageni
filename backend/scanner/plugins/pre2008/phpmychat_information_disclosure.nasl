# OpenVAS Vulnerability Test
# $Id: phpmychat_information_disclosure.nasl 14336 2019-03-19 14:53:10Z mmartin $
# Description: phpMyChat Information Disclosure
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16056");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("phpMyChat Information Disclosure");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securiteam.com/unixfocus/6D00S0KC0S.html");

  script_tag(name:"summary", value:"phpMyChat is an easy-to-install, easy-to-use multi-room
 chat based on PHP and a database, supporting MySQL,
 PostgreSQL, and ODBC.

 This set of script may allow an attacker to cause an information
 disclosre vulnerability allowing an attacker to cause the
 program to reveal the SQL username and password, the phpMyChat's
 administrative password, and other sensitive information.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

debug = 0;

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);

dirs = make_list_unique(cgi_dirs(port:port), "/forum", "/forum/chat", "/chat", "/chat/chat", "/"); # The /chat/chat isn't a mistake

foreach dir (dirs) {

  if( dir == "/" ) dir = "";

  if (debug) { display("dir: ", dir, "\n"); }

  req = http_get(item: dir + "/setup.php3?next=1", port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
  if( r == NULL )exit(0);

  if (debug) { display("r: [", r, "]\n"); }

  if(("C_DB_NAME" >< r) || ("C_DB_USER" >< r) || ("C_DB_PASS" >< r)) {
    security_message(port:port);
    exit(0);
 }
}

exit(99);