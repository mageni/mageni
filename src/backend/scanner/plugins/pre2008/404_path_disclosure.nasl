###############################################################################
# OpenVAS Vulnerability Test
#
# Non-Existent Page Physical Path Disclosure Vulnerability
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11714");
  script_version("2019-05-24T11:20:30+0000");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3341, 4035, 4261, 5054, 8075);
  # Note: the way the test is made will lead to detecting some
  # path disclosure issues which might be checked by other plugins
  # (like #11226: Oracle9i jsp error). I have reviewed the reported
  # "path disclosure" errors from bugtraq and the following list
  # includes bugs which will be triggered by the NASL script. Some
  # other "path disclosure" bugs in webservers might not be triggered
  # since they might depend on some specific condition (execution
  # of a cgi, options..)
  # jfs - December 2003
  script_cve_id("CVE-2003-0456", "CVE-2001-1372");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Non-Existent Page Physical Path Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your server or reconfigure it.");

  script_tag(name:"summary", value:"Your web server reveals the physical path of the webroot
  when asked for a non-existent page.

  Whilst printing errors to the output is useful for debugging applications,
  this feature should not be enabled on production servers.");

  script_tag(name:"affected", value:"Pi3Web version 2.0.0 is known to be vulnerable. Other versions
  might be affected as well.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

exts = make_list( ".", "/", ".html", ".htm", ".jsp", ".shtm", ".shtml", ".cfm" );
asp_exts = make_list( ".asp", ".aspx" );
php_exts = make_list( ".php", ".php3", ".php4", ".php5", ".php7" );

port = get_http_port( default:80 );

# Choose file to request based on what the remote host is supporting
if( can_host_asp( port:port ) && can_host_php( port:port ) ) {
  exts = make_list( exts, asp_exts, php_exts );
} else if( can_host_asp( port:port ) ) {
  exts = make_list( exts, asp_exts );
} else if( can_host_php( port:port ) ) {
  exts = make_list( exts, php_exts );
}

foreach ext( exts ) {

  file = "non-existent-" + rand();
  url = "/" + file + ext;
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  if( isnull( res ) ) continue;

  if( egrep( string:res, pattern:strcat("[C-H]:(\\[A-Za-z0-9_.-])*\\", file, "\\", ext ) ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }

  # Unix like path
  if( egrep( string:res, pattern:strcat("(/[A-Za-z0-9_.+-])+/", file, "/", ext ) ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );