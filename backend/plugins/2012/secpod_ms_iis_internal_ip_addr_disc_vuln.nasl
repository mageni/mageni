###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iis_internal_ip_addr_disc_vuln.nasl 14187 2019-03-14 14:09:52Z cfischer $
#
# Microsoft IIS IP Address/Internal Network Name Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902796");
  script_version("$Revision: 14187 $");
  script_bugtraq_id(3159);
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 15:09:52 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-23 15:45:49 +0530 (Thu, 23 Feb 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Microsoft IIS IP Address/Internal Network Name Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/834141/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3159/info");
  script_xref(name:"URL", value:"http://support.microsoft.com/default.aspx?scid=KB;EN-US;Q218180");
  script_xref(name:"URL", value:"http://www.juniper.net/security/auto/vulnerabilities/vuln3159.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web Servers");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain internal IP
  address or internal network name, which could assist in further attacks against the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error while processing 'GET' request. When
  MS IIS receives a GET request without a host header, the Web server will reveal the IP address of the
  server in the content-location field or the location field in the TCP header in the response.");

  script_tag(name:"solution", value:"Apply the hotfix for IIS 6.0");

  script_tag(name:"summary", value:"The host is running Microsoft IIS Webserver and is prone to
  IP address disclosure vulnerability.");

  script_tag(name:"affected", value:"Microsoft Internet Information Services version 4.0, 5.0, 5.1 and 6.0");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/834141/#top");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

foreach dir( make_list_unique("/", "/scripts", "/admin", "/webdav", cgi_dirs(port:port)))
{
  ip = string("http://", get_host_name(), dir);

  sndReq = string("GET ", dir, " HTTP/1.0 \r\n\r\n");
  rcvRes = http_send_recv(port:port, data:sndReq);

  pattern = string("Location: ", ip);

  if(rcvRes && pattern >< rcvRes &&
     egrep(pattern:"^HTTP/.* 302 Object Moved", string:rcvRes))
  {
    security_message(port);
    exit(0);
  }
}