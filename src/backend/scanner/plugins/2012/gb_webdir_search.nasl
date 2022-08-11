###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webdir_search.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Search for specified webdirs
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103437");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-02-27 16:32:37 +0100 (Mon, 27 Feb 2012)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Search for specified dirs");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"This Plugin is searching for the specified webdirs.");

  script_add_preference(name:"Search for dir(s)", value:"/admin;/manager", type:"entry");
  script_add_preference(name:"Valid http status codes indicating that a directory was found", value:"200;301;302;401;403", type:"entry");
  script_add_preference(name:"Run this Plugin", type:"checkbox", value:"no");

  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

run = script_get_preference("Run this Plugin");
if("yes" >!< run)exit(0);

include("http_func.inc");

if(http_is_cgi_scan_disabled()) {
  log_message(port:0, data:"Plugin was enabled but CGI Scanning was disabled via Scan Config, not running this test.");
  exit(0);
}

function check_response(resp, codes) {

  local_var resp,code, codes;

  foreach code (codes) {

    if(!isnull(code)) {
      if(ereg(pattern:"HTTP/1\.[0|1] " + code, string:resp)) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

search_dirs = script_get_preference("Search for dir(s)");
http_codes  = script_get_preference("Valid http status codes indicating that a directory was found");

dirs = split(search_dirs, sep:";", keep:FALSE);
if(max_index(dirs) < 1) exit(0);

codes = split(http_codes, sep:";", keep:FALSE);
if(max_index(codes) < 1) exit(0);

port = get_http_port(default:80);
host = http_host_name(dont_add_port:TRUE);
if(http_get_no404_string(port:port, host:host)) exit(0);

foreach dir (dirs) {

  dir = chomp(dir);
  if(!ereg(pattern: "^/", string: dir)) dir = "/" + dir;

  req = http_get(item:dir, port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);
  if( isnull( buf ) || buf =~ "HTTP/1\.[0|1] 404") continue;

  if(check_response(resp:buf, codes:codes)) {
    report += 'Found dir ' + dir + '\n';
  }
}

if(report) {
  log_message(port:port, data:report);
  exit(0);
}

exit(0);