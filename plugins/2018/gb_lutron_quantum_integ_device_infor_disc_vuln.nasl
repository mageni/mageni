###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lutron_quantum_integ_device_infor_disc_vuln.nasl 9180 2018-03-22 15:38:54Z cfischer $
#
# Lutron Quantum BACnet Integration Devices Information Disclosure Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#                                                                                                                                               # Copyright:
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

CPE = "cpe:/a:lutron:device";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812953");
  script_version("$Revision: 9180 $");
  script_cve_id("CVE-2018-7276");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-03-22 16:38:54 +0100 (Thu, 22 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-02-27 17:23:35 +0530 (Tue, 27 Feb 2018)");
  script_name("Lutron Quantum BACnet Integration Devices Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is running Lutron Quantum BACnet
  Integration device and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether we are able to read sensitive information or not.");

  script_tag(name:"insight", value:"The flaw exist due to broken access control
  mechanism in the device.");

  script_tag(name:"impact" , value:"Successful exploitation will allow remote
  attackers to obtain potentially sensitive information via a '/DbXmlInfo.xml'
  request.

  Impact Level: Application");

  script_tag(name:"affected" , value:"Lutron Quantum BACnet Integration 2.0
  devices with firmware 3.2.243.");

  script_tag(name:"solution" , value:"No solution or patch is available as of
  28th Feb, 2018. Information regarding this issue will be updated once solution
  details are available. For updates refer to http://www.lutron.com/");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"exploit");
  script_xref(name : "URL" , value : "http://misteralfa-hack.blogspot.in/2018/02/bacnet-entrando-en-materia.html");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_lutron_devices_detect.nasl");
  script_mandatory_keys("lutron/detected");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!lutPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!get_app_location(cpe:CPE, port:lutPort, nofork: TRUE)){
  exit(0);
}

url = '/DbXmlInfo.xml';

if(http_vuln_check(port:lutPort, url:url, pattern:"<Latitude>[ 0-9.-]+</Latitude>",
                   extra_check:make_list("<Copyright>Copyright.* Lutron Electronics",
                   "<Longitude>[ 0-9.-]+</Longitude>")))
{
  report = report_vuln_url(port:lutPort, url:url);
  security_message(port:lutPort, data: report);
  exit(0);
}
exit(0);
