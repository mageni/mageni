###############################################################################
# OpenVAS Vulnerability Test
#
# PQI Air Pen Express Wireless Router Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:pqi:air:pen:express";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807536");
  script_version("2019-05-10T14:24:23+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2016-04-07 11:07:14 +0530 (Thu, 07 Apr 2016)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("PQI Air Pen Express Wireless Router Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host has PQI Air Pen Express
  Wireless Router and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and
  check whether it is able read the sensitive information");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Not restricting some files which are containing sensitive information.

  - Insufficient validation of user supplied input via parameters 'mssid_0',
  'ssid', 'hostname', 'admpass' in Basic Wireless Settings, 'hostname', in
  Wide Area Network (WAN) Settings and 'addURLFilter', 'addHostFilter'
  in Webs URL Filter Settings.

  - The users are allowed to set the administrative credential.

  - An insecure default permission setting.

  - Any action, whether sensitive or not is transmitted in plain text because
    HTTPS is not used");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information and to execute
  arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.");

  script_tag(name:"affected", value:"PQI Air Pen Express - Wireless Router 6W51-0000R2 and 6W51-0000R2XXX");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39659");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pqi_air_pen_express_remote_detect.nasl");
  script_mandatory_keys("PQI/Air/Pen/Express/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!pqiPort = get_app_port(cpe:CPE)){
  exit(0);
}

url = "/cgi-bin/ExportSettings.sh";

if(http_vuln_check(port:pqiPort, url:url, check_header:TRUE,
   pattern:"staWirelessMode",
   extra_check:make_list("wanConnectionMode", "HostName", "lan_ipaddr", "WAN_MAC_ADDR")))
{
  report = report_vuln_url( port:pqiPort, url:url );
  security_message(port:pqiPort, data:report);
  exit(0);
}
