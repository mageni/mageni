# OpenVAS Vulnerability Test
# Description: IIS 5 .printer ISAPI filter applied
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added link to the Bugtraq message archive
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
  script_oid("1.3.6.1.4.1.25623.1.0.10661");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IIS 5 .printer ISAPI filter applied");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Matt Moore");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("IIS/banner");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/1/181109");

  script_tag(name:"solution", value:"To unmap the .printer extension:

  1.Open Internet Services Manager.

  2.Right-click the Web server choose Properties from the context menu.

  3.Master Properties

  4.Select WWW Service -> Edit -> HomeDirectory -> Configuration

  and remove the reference to .printer from the list.");

  script_tag(name:"summary", value:"Remote Web server supports Internet Printing Protocol.");

  script_tag(name:"insight", value:"IIS 5 has support for the Internet Printing Protocol(IPP), which is
  enabled in a default install. The protocol is implemented in IIS5 as an ISAPI extension. At least one
  security problem (a buffer overflow) has been found with that extension in the past, so we recommend
  you disable it if you do not use this functionality.");

  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

sig = get_http_banner(port:port);
if(!sig || "IIS" >!< sig)
  exit(0);

url = "/NULL.printer";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(!res)
  exit(0);

if("Error in web printer install" >< res) {
  report = report_vuln_url(port:port, url:url);
  log_message(port:port, data:report);
  exit(0);
}

exit(99);