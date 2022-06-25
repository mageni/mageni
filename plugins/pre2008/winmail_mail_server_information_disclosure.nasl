# OpenVAS Vulnerability Test
# $Id: winmail_mail_server_information_disclosure.nasl 14336 2019-03-19 14:53:10Z mmartin $
# Description: Winmail Mail Server Information Disclosure
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
  script_oid("1.3.6.1.4.1.25623.1.0.16042");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Winmail Mail Server Information Disclosure");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software");
  script_tag(name:"summary", value:"The remote host is running Winmail Server.

 Winmail Server is an enterprise class mail server software system
 offering a robust feature set, including extensive security
 measures. Winmail Server supports SMTP, POP3, IMAP, Webmail, LDAP,
 multiple domains, SMTP authentication, spam protection, anti-virus
 protection, SSL/TLS security, Network Storage, remote access,
 Web-based administration, and a wide array of standard email options
 such as filtering, signatures, real-time monitoring, archiving,
 and public email folders.");
  script_tag(name:"impact", value:"Three scripts that come with the program (chgpwd.php, domain.php and user.php)
 allow a remote attacker to disclose sensitive information about the remote host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

debug = 0;

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);

function check(loc)
{

 if(loc == "/") loc = "";

 if (debug) { display("loc: ", loc, "\n"); }
 req = http_get(item: loc + "/chgpwd.php", port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if (debug) { display("r: [", r, "]\n"); }
 if(("Call to a member function on a non-object in" >< r) && ("Fatal error" >< r) &&
    ("Winmail" >< r) && ("admin" >< r) && ("chgpwd.php" >< r))
 {
 	security_message(port:port);
	exit(0);
 }
}

dirs = make_list_unique(cgi_dirs(port:port), "/admin");

foreach dir (dirs)
{
 check(loc:dir);
}

exit(99);