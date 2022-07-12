# OpenVAS Vulnerability Test
# $Id: iis_webdav_lock_memory_leak.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: IIS 5.0 WebDav Memory Leakage
#
# Authors:
# Gregory Duchemin <plugin@intranode.com>
#
# Copyright:
# Copyright (C) 2001 INTRANODE
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
  script_oid("1.3.6.1.4.1.25623.1.0.10732");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2736);
  script_cve_id("CVE-2001-0337");
  script_name("IIS 5.0 WebDav Memory Leakage");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 INTRANODE");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/banner");

  script_tag(name:"solution", value:"Download Service Pack 2/hotfixes from Microsoft.");

  script_tag(name:"summary", value:"The WebDav extensions (httpext.dll) for Internet Information
  Server 5.0 contains a flaw that may allow a malicious user to consume all available memory on
  the target server by sending many requests using the LOCK method associated to a non
  existing filename.

  This concern not only IIS but the entire system since the flaw can
  potentially exhausts all system memory available.");

  script_tag(name:"affected", value:"Vulnerable systems: IIS 5.0 ( httpext.dll versions prior to 0.9.3940.21 )

  Immune systems: IIS 5 SP2( httpext.dll version 0.9.3940.21)");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

sig = get_http_banner(port:port);
if(!egrep(pattern:"^Server:.*IIS", string:sig))
  exit(0);

host = http_host_name(port:port);

quote = raw_string(0x22);
poison = string("PROPFIND / HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: text/xml\r\n",
                "Content-Length: 110\r\n\r\n",
                "<?xml version=", quote, "1.0", quote, "?>\r\n",
                "<a:propfind xmlns:a=", quote, "DAV:", quote, ">\r\n",
                " <a:prop>\r\n",
                "  <a:displayname:/>\r\n",
                " </a:prop>\r\n",
                "</a:propfind>\r\n");

soc = http_open_socket(port);
if(!soc) exit(0);

send(socket:soc, data:poison);
code = recv_line(socket:soc, length:1024);
http_close_socket(soc);

if(!code || "HTTP/1.1 207" >!< code)
  exit(0);

security_message(port:port);
exit(0);