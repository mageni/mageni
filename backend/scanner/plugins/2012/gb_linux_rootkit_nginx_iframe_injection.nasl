###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_linux_rootkit_nginx_iframe_injection.nasl 13859 2019-02-26 05:27:33Z ckuersteiner $
#
# 64-bit Debian Linux Rootkit with nginx Doing iFrame Injection
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802045");
  script_version("$Revision: 13859 $");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 06:27:33 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-12-03 13:43:19 +0530 (Mon, 03 Dec 2012)");

  script_name("64-bit Debian Linux Rootkit with nginx Doing iFrame Injection");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Nov/94");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Nov/172");
  script_xref(name:"URL", value:"http://blog.crowdstrike.com/2012/11/http-iframe-injecting-linux-rootkit.html");
  script_xref(name:"URL", value:"http://www.securelist.com/en/blog/208193935/New_64_bit_Linux_Rootkit_Doing_iFrame_Injections");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Malware");
  script_dependencies("nginx_detect.nasl");
  script_mandatory_keys("nginx/installed");

  script_tag(name:"impact", value:"Successful iframe injection leads redirecting to some malicious sites.");

  script_tag(name:"affected", value:"64-bit Debian Squeeze (kernel version 2.6.32-5-amd64) with nginx.");

  script_tag(name:"insight", value:"64-bit Debian Squeeze Linux Rootkit in combination with nginx launching
  iframe injection attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Debian Squeeze Linux Rootkit with nginx and
  is prone to iframe injection.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

bad_req = string( "GET / HTTP/1.1\r\n", "Hostttt ", get_host_name(), "\r\n\r\n");

## Send bad request
bad_res = http_keepalive_send_recv(port:port, data:bad_req);

if("HTTP/1.1 400 Bad Request" >< bad_res && "Server: nginx" >< bad_res &&
   egrep(pattern:"<iframe\s+src=.*</iframe>", string:bad_res, icase:TRUE)){
  security_message(port:port);
  exit(0);
}

exit(99);
