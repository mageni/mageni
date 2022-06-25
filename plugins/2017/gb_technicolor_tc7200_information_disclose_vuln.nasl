###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_technicolor_tc7200_information_disclose_vuln.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# Technicolor TC7200 Information Disclosure Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/o:technicolor:tc7200_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811656");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2014-1677");
  script_bugtraq_id(65774);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-08 17:01:34 +0530 (Fri, 08 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Technicolor TC7200 Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is running Technicolor TC7200
  and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The web interface does not use cookies at all
  and does not check the IP address of the client. If admin login is successful,
  every user from the LAN can access the management interface.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers
  to obtain sensitive information.");

  script_tag(name:"affected", value:"Technicolor TC7200 with firmware
  STD6.01.12.");

  script_tag(name:"solution", value:"Update the TC7200 firmware to STD6.02 or above");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/31894/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/538955/100/0/threaded");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_technicolor_tc7200_snmp_detect.nasl");
  script_mandatory_keys("technicolor/detected");
  script_require_udp_ports("Services/udp/snmp", 161);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!tecPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!vers = get_app_version(cpe:CPE, port:tecPort)){
  exit(0);
}

if(vers == "STD6.01.12")
{
  report = report_fixed_ver(installed_version: vers, fixed_version: "STD6.02");
  security_message(port: tecPort, data: report, proto: "udp");
  exit(0);
}
exit(0);
