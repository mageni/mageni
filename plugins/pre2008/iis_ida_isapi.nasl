# OpenVAS Vulnerability Test
# $Id: iis_ida_isapi.nasl 13685 2019-02-15 10:06:52Z cfischer $
# Description: IIS .IDA ISAPI filter applied
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
# Modified by rd to have a language independent pattern matching, thanks
# to the remarks from Nicolas Gregoire <ngregoire@exaprobe.com>
#
# Copyright:
# Copyright (C) 2001 Matt Moore
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10695");
  script_version("$Revision: 13685 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:06:52 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2880);
  script_cve_id("CVE-2001-0500");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("IIS .IDA ISAPI filter applied");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("This script is Copyright (C) 2001 Matt Moore");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("IIS/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Indexing Service filter is enabled on the remote Web server.");

  script_tag(name:"insight", value:"The IIS server appears to have the .IDA ISAPI filter mapped.

  At least one remote vulnerability has been discovered for the .IDA
  (indexing service) filter. This is detailed in Microsoft Advisory
  MS01-033, and gives remote SYSTEM level access to the web server.

  It is recommended that even if you have patched this vulnerability that
  you unmap the .IDA extension, and any other unused ISAPI extensions
  if they are not required for the operation of your site.");

  script_tag(name:"solution", value:"To unmap the .IDA extension:

  1.Open Internet Services Manager.

  2.Right-click the Web server choose Properties from the context menu.

  3.Master Properties

  4.Select WWW Service -> Edit -> HomeDirectory -> Configuration
  and remove the reference to .ida from the list.

  In addition, you may wish to download and install URLSCAN from the
  Microsoft Technet web site. URLSCAN, by default, blocks all .ida
  requests to the IIS server.");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if( http_get_is_marked_embedded( port:port ) )
  exit( 0 );

sig = get_http_banner(port:port);
if ( sig && "IIS" >!< sig )
  exit(0);

req = http_get(item:"/NULL.ida", port:port);
soc = http_open_socket(port);
if(!soc)
  exit(0);

send(socket:soc, data:req);
r = http_recv(socket:soc);
http_close_socket(soc);
look = strstr(r, "<HTML>");
look = look - string("\r\n");
if(egrep(pattern:"^.*HTML.*IDQ.*NULL\.ida.*$", string:look))
  security_message(port);
