###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flir_brickstream_sensors_incorrect_access_control_vuln.nasl 12937 2019-01-04 07:15:01Z asteins $
#
# Flir Brickstream Sensors Incorrect Access Control Vulnerability
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

CPE = "cpe:/a:flir:brickstream_sensor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812370");
  script_version("$Revision: 12937 $");
  script_cve_id("CVE-2018-3813");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 08:15:01 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-01-02 17:29:37 +0530 (Tue, 02 Jan 2018)");
  script_name("Flir Brickstream Sensors Incorrect Access Control Vulnerability");

  script_tag(name:"summary", value:"The host is running Flir Brickstream Sensor
  and is prone to an incorrect access control vulnerability.");

  script_tag(name:"vuldetect", value:"Sends the crafted http GET request
  and checks whether it is able to access the administration or not.");

  script_tag(name:"insight", value:"The flaw exists due to incorrect access control
  measures taken by the sensor.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to access administration of the device.");

  script_tag(name:"affected", value:"FLIR Brickstream 2300 devices");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://misteralfa-hack.blogspot.in/2018/01/brickstream-recuento-y-seguimiento-de.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_flir_brickstream_sensors_detect.nasl");
  script_mandatory_keys("Flir/Brickstream/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!flirPort = get_app_port(cpe:CPE)){
  exit(0);
}

url = "/getConfigExportFile.cgi";

if (http_vuln_check(port:flirPort, url:url , pattern: "AVI_USER_ID=",
                    extra_check:make_list("AVI_USER_PASSWORD=", "AVI_SERVER_ADDRESS=", "AVI_USER_ID="),
                    check_header: TRUE)) {
  report = report_vuln_url(port:flirPort, url:url);
  security_message(port:flirPort, data:report);
  exit(0);
}

exit(99);
