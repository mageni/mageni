###############################################################################
# OpenVAS Vulnerability Test
# $Id: propfind_internal_ip.nasl 10418 2018-07-05 11:22:00Z cfischer $
#
# Private IP address Leaked using the PROPFIND method
#
# Authors:
# Anthony R. Plastino III <tplastino@sses.net>
#
# Copyright:
# Copyright (C) 2004 Sword & Shield Enterprise Security, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.12113");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-0422");
  script_name("Private IP address Leaked using the PROPFIND method");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) Sword & Shield Enterprise Security, Inc., 2004");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("keys/is_private_addr", "Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://support.microsoft.com/default.aspx?scid=KB%3BEN-US%3BQ218180&ID=KB%3BEN-US%3BQ218180");
  script_xref(name:"URL", value:"http://www.nextgenss.com/papers/iisrconfig.pdf");

  script_tag(name:"solution", value:"See the references for an update / more information.");

  script_tag(name:"summary", value:"The remote web server leaks a private IP address through the WebDAV interface. If this
  web server is behind a Network Address Translation (NAT) firewall or proxy server, then
  the internal IP addressing scheme has been leaked.

  This is typical of IIS 5.0 installations that are not configured properly.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); #TBD: remote_banner?

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("network_func.inc");

if( is_private_addr() )
  exit( 0 );

port = get_http_port( default:80 );
host = http_host_name( port:port );

# nb: Build the custom HTTP/1.0 request for the server to respond to
req = 'PROPFIND / HTTP/1.0\r\n' +
      'Host: ' + host + '\r\n' +
      'Content-Length: 0\r\n\r\n';
buf = http_keepalive_send_recv( port:port, data:req );

# now check for RFC 1918 addressing in the returned data - not necessarily in the header
# Ranges are: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
# TBD: regex for all IPv6 addresses and then pass to is_private_addr(addr, use_globals:FALSE) ?
private_ip = eregmatch( pattern:"([^12]10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})", string:buf );
if( ! isnull( private_ip ) && private_ip !~ "Oracle.*/10\." ) {
  report = "This web server leaks the following private IP address: " + private_ip[0] + '\n\n';
  report += report_vuln_url( port:port, url:"/" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );