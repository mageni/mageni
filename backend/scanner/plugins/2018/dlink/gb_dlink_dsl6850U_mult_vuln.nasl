###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dsl6850U_mult_vuln.nasl 12274 2018-11-09 07:51:05Z cfischer $
#
# D-Link DSL-6850U Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE_PREFIX = "cpe:/o:dlink";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812376");
  script_version("$Revision: 12274 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-09 08:51:05 +0100 (Fri, 09 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-01-03 15:39:16 +0530 (Wed, 03 Jan 2018)");
  script_name("D-Link DSL-6850U Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dsl_detect.nasl", "gb_dlink_dap_detect.nasl", "gb_dlink_dir_detect.nasl", "gb_dlink_dwr_detect.nasl");
  script_mandatory_keys("Host/is_dlink_device"); # nb: Experiences in the past have shown that various different devices are affected
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3588");
  script_xref(name:"URL", value:"http://www.dlink.com/");

  script_tag(name:"summary", value:"The host is a D-Link DSL-6850U router
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send the crafted HTTP GET request
  and check whether it is possible to access the administration GUI or not.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Default account 'support' with password 'support' which cannot be disabled.

  - Availability of the shell interface although only a set of commands, but
  commands can be combined using logical AND, logical OR.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to access administration of the device and execute arbitrary code
  on the affected system.");

  script_tag(name:"affected", value:"D-Link DSL-6850U versions BZ_1.00.01 - BZ_1.00.09.
  Other devices, models or versions might be also affected.");

  script_tag(name:"solution", value:"Apply the latest security patches from the
  vendor.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www", first_cpe_only:TRUE ) ) exit( 0 );

port = infos["port"];
CPE = infos["cpe"];

if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

url = dir + "/lainterface.html";
res = http_get_cache( item:url, port:port );
if( ! res || res !~ "^HTTP/1\.[01] 401" ) exit( 0 );

host = http_host_name( port:port );

# Base64(support:support) == c3VwcG9ydDpzdXBwb3J0
req = string( "GET ", url, " HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "Authorization: Basic c3VwcG9ydDpzdXBwb3J0\r\n",
              "\r\n");
res = http_keepalive_send_recv( port:port, data:req );

if( res && "WAN SETTINGS" >< res && "value='3G Interface" >< res && "menu.html" >< res &&
    "TabHeader=th_setup" >< res && 'src="util.js"' >< res && 'src="language_en.js"' >< res ) {
  report = "It was possible to login with the default account 'support:support' at the following URL: " + report_vuln_url( port:port, url:url, url_only:TRUE );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );