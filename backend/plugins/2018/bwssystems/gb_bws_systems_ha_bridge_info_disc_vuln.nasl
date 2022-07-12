###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bws_systems_ha_bridge_info_disc_vuln.nasl 13655 2019-02-14 07:53:42Z ckuersteiner $
#
# BWS Systems HA-Bridge '#!/system' URI Information Disclosure Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/h:bws_systems:ha_bridge";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813627");
  script_version("$Revision: 13655 $");
  script_cve_id("CVE-2018-12923");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 08:53:42 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-07-03 12:50:41 +0530 (Tue, 03 Jul 2018)");

  script_name("BWS Systems HA-Bridge '#!/system' URI Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is running BWS Systems HA-Bridge
  and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check if response is disclosing sensitive information or not.");

  script_tag(name:"insight", value:"The flaw is due to improper access control
  mechanism in the '#!/system' URI.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"BWS Systems HA-Bridge.");

  script_tag(name:"solution", value:"No known solution is available as of 14th February, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"https://www.seebug.org/vuldb/ssvid-97373");
  script_xref(name:"URL", value:"http://bwssystems.com/#/habridge");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_bws_systems_ha_bridge_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("BWSSystems/HA/Bridge/installed");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! bmsPort = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:bmsPort ) ) exit( 0 );
if( dir == "/" ) dir = "";

url = dir + "/system/settings";

if( http_vuln_check(port:bmsPort, url:url, check_header:TRUE,
                    pattern:'configfile":','serverport":[0-9]+',
                    extra_check:make_list('upnpdevicedb":', 'numberoflogmessages":')))
{
  report = report_vuln_url(port:bmsPort, url:url);
  security_message( port:bmsPort, data:report );
  exit(0);
}
exit(0);
