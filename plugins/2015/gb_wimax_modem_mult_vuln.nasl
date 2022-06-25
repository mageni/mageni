###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wimax_modem_mult_vuln.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# WIMAX Modem Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806799");
  script_version("$Revision: 11408 $");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-12-15 09:04:51 +0530 (Tue, 15 Dec 2015)");
  script_name("WIMAX Modem Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38914");

  script_tag(name:"summary", value:"This host is installed with WIMAX Modem
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to retrieve sensitive information or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The '/cgi-bin/diagnostic.cgi' which fails to properly restrict access.

  - The '/cgi-bin/pw.cgi' which fails to properly restrict access.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to to read sensitive information and set it on his own modem and
  send a packet to the modem for crashing/downgrading/DOS and to obtain the
  control of similar modem in order to launch DOS or DDOS attacks on targets.");

  script_tag(name:"affected", value:"WIMAX MT711x version V_3_11_14_9_CPE");

  script_tag(name:"solution", value:"No known solution was made available for
  at least one year since the disclosure of this vulnerability. Likely none will be
  provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");

wimaxPort = get_http_port(default:80);

url = string("/cgi-bin/multi_wifi.cgi");

req = http_get(item:url, port:wimaxPort);
res = http_send_recv(port:wimaxPort,data:req);

if("SeowonCPE" >< res && "wifi_mode" >< res && "auth_mode" >< res &&
   "network_key" >< res && "w_ssid" >< res && "wifi_setup" >< res &&
   ">WiMAX" >< res)
{
  report = report_vuln_url(port:wimaxPort, url:url);
  security_message(port:wimaxPort, data:report);
  exit(0);
}
