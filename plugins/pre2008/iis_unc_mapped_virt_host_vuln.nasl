###############################################################################
# OpenVAS Vulnerability Test
# $Id: iis_unc_mapped_virt_host_vuln.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Microsoft IIS UNC Mapped Virtual Host Vulnerability
#
# Authors:
# tony@libpcap.net, http://libpcap.net
#
# Copyright:
# Copyright (C) 2001 tony@libpcap.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.11443");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1081);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2000-0246");
  script_name("Microsoft IIS UNC Mapped Virtual Host Vulnerability");
  script_copyright("Copyright (C) 2001 tony@libpcap.net");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Your IIS webserver allows the retrieval of ASP/HTR source code.");

  script_tag(name:"impact", value:"An attacker can use this vulnerability to see how your
  pages interact and find holes in them to exploit.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if ( ! can_host_asp( port:port ) ) exit( 0 );
host = http_host_name( dont_add_port:TRUE );

# common ASP files
check_files = make_list( "/index.asp%5C", "/default.asp%5C", "/login.asp%5C" );

files = http_get_kb_file_extensions( port:port, host:host, ext:"asp" );
if( ! isnull( files ) ) {
  files = make_list( files );
  check_files = make_list( check_files, files[0] + "%5C" );
}

foreach check_file( check_files ) {

  req = http_get( item:check_file, port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  if( isnull( res ) ) exit( 0 );

  if( ereg( pattern:"^HTTP/1\.[01] 200 .*", string:res ) &&
      "Content-Type: application/octet-stream" >< res ) {
    report = report_vuln_url( port:port, url:check_file );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
