###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_v-cms_mult_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# V-CMS Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902498");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-4826", "CVE-2011-4827", "CVE-2011-4828");
  script_bugtraq_id(50706);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-23 12:08:49 +0530 (Fri, 23 Dec 2011)");
  script_name("V-CMS Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46861");
  script_xref(name:"URL", value:"http://bugs.v-cms.org/view.php?id=53");
  script_xref(name:"URL", value:"http://bugs.v-cms.org/changelog_page.php");
  script_xref(name:"URL", value:"http://www.autosectools.com/Advisory/V-CMS-1.0-Arbitrary-Upload-236");
  script_xref(name:"URL", value:"http://www.autosectools.com/Advisory/V-CMS-1.0-Reflected-Cross-site-Scripting-234");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of a vulnerable
  site and to cause SQL Injection attack to gain sensitive information.");

  script_tag(name:"affected", value:"V-CMS version 1.0 and prior.");

  script_tag(name:"insight", value:"The flaws are due to improper validation of user-supplied input
  via the 'p' parameter to redirect.php and 'user' parameter to process.php and
  'includes/inline_image_upload.php' script, which fails to restrict non-logged
  in users to upload any files.");

  script_tag(name:"solution", value:"Update V-CMS to version 1.1 or later.");

  script_tag(name:"summary", value:"This host is running V-CMS and is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/vcms", "/v-cms", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";

  res = http_get_cache( port:port, item:url );

  if( ">V-CMS-Powered by V-CMS" >< res ) {

    url = dir + "/redirect.php?p=%3C/script%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E%27";
    req = http_get( port:port, item:url );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( res =~ "^HTTP/1\.[01] 200" && "</script><script>alert(document.cookie)</script>" >< res ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );