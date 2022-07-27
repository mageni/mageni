###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winrm_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Detection of WinRM
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103923");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-03-19 12:39:47 +0100 (Wed, 19 Mar 2014)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("WinRM Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 5985, 5986);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Windows Remote Management (WinRM) is running at this port.

  Windows Remote Management (WinRM) is the Microsoft implementation of
  WS-Management Protocol, a standard Simple Object Access Protocol (SOAP)-based,
  firewall-friendly protocol that allows hardware and operating systems,
  from different vendors, to interoperate.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");

port = get_http_port( default:5985 );
host = http_host_name( port:port );

vt_strings = get_vt_strings();

req = 'POST /wsman HTTP/1.1\r\n' +
      'Authorization: Negotiate TlRMTVNTUAABAAAAt4II4gAAAAAAAAAAAAAAAAAAAAAGAHIXAAAADw==\r\n' +
      'Content-Type: application/soap+xml;charset=UTF-8\r\n' +
      'User-Agent: Microsoft WinRM Client ' + vt_strings["default"] + '\r\n' +
      'Host: ' + host + '\r\n' +
      'Content-Length: 0\r\n' +
      'Connection: Close\r\n' +
      '\r\n';

buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "HTTP/1\.. 401" && "Server: Microsoft-HTTPAPI/" >< buf && "Negotiate TlRMTVNT" >< buf )
{
  register_service( port:port, ipproto:"tcp", proto:"winrm" );
  log_message( port:port );
}

exit( 0 );