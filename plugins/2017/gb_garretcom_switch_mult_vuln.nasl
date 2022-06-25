##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_garretcom_switch_mult_vuln.nasl 12260 2018-11-08 12:46:52Z cfischer $
#
# Belden GarrettCom 6K/10K Switches Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/o:garrettcom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106834");
  script_version("$Revision: 12260 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-08 13:46:52 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-05-26 16:11:38 +0700 (Fri, 26 May 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Belden GarrettCom 6K/10K Switches Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_garrettcom_switch_detect.nasl");
  script_mandatory_keys("garretcom_switch/detected", "garretcom_switch/model");

  script_tag(name:"summary", value:"Belden GarrettCom 6K and 10KT (Magnum) series network switches are
  prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Belden GarrettCom 6K and 10KT (Magnum) series network switches are
  prone to multiple vulnerabilities:

  - A certain hardcoded string can be used to bypass web authentication

  - Unprivileged but authenticated users can potentially elevate their access to manager level

  - Issuing a certain form of URL against the device's web server can lead to a buffer overflow in the HTTP Server
  which  can  can  lead  to  memory corruption, possibly  including  remote  code execution

  - Firmware version 4.6.0 devices use the same default SSL certificates and the documentation is not clear that
  users must install their own keys and certificates on the switch to override the default

  - The switches support a number of weak SSL ciphers such as 56-bit DES, RC4, MD5 based MACs

  - HTTP session key generation is weak");

  script_tag(name:"impact", value:"An unauthenticated attacker may gain complete access to the device.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP request to try to bypass authentication and checks
  the response.");

  script_tag(name:"solution", value:"Update to firmware version 4.7.7 or later.");

  script_xref(name:"URL", value:"http://www.belden.com/docs/upload/Belden-GarrettCom-MNS-6K-10K-Security-Bulletin-BSECV-2017-8.pdf");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42035/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE, service: "www"))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

model = get_kb_item("garretcom_switch/model");
if (!model || model !~ "(6k|10k)")
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/gc/service.php?a=getSystemInformation&key=GoodKey';

if (http_vuln_check(port: port, url: url, pattern: "<sysversion val=", check_header: TRUE,
                    extra_check: "<serialnumber val=")) {
  report = "It was possible to access the device information page without proper authentication at " +
           report_vuln_url(port: port, url: url, url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
