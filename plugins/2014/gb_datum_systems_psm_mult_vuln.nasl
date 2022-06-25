###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_datum_systems_psm_mult_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# Datum Systems Satellite Modem Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804477");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2014-2951", "CVE-2014-2950");
  script_bugtraq_id(68515, 68514);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-07-30 14:56:40 +0530 (Wed, 30 Jul 2014)");
  script_name("Datum Systems Satellite Modem Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Datum Systems Satellite Modem and is prone to multiple
  vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted default credential via HTTP GET request and check whether it
  is able to login or not.");
  script_tag(name:"insight", value:"- The FTP service being enabled by default without authentication mechanisms.
  This may allow a remote attacker to gain access to potentially sensitive
  information.

  - The admin user account has a password of 'admin', which is publicly known and
  documented. This allows remote attackers to trivially gain privileged access
  to the SnIP operating system.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to trivially gain privileged
  access to the device, execute arbitrary commands and gain access to arbitrary files.");
  script_tag(name:"affected", value:"Datum Systems PSM-4500 and PSM-500 series satellite modem");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/917348");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/94483");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("SnIP/banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

kPort = get_http_port(default:80);

kBanner = get_http_banner(port: kPort);
if('WWW-Authenticate: Basic realm="SnIP' >!< kBanner) exit(0);

credentials = "admin:admin";
userpass = base64(str:credentials);

host = http_host_name(port:kPort);

sipReq = 'GET /sys-status.html HTTP/1.1\r\n' +
         'Host: ' +  host + '\r\n' +
         'Authorization: Basic ' + userpass + '\r\n' +
         '\r\n';

sipRes = http_keepalive_send_recv( port:kPort, data:sipReq, bodyonly:FALSE );

if(sipRes =~ "HTTP/1\.. 200"  && "LAN Ethernet" >< sipRes &&
   ">SnIP Ver:<" >< sipRes && "HDLC_IPADDR" >< sipRes)
{
  defaults = str_replace( string:credentials, find:":", replace:"/" );
  report = 'It was possible to login using the following credentials:\n\n' + defaults;
  security_message(port:kPort, data:report );
  exit(0);
}

exit(99);
