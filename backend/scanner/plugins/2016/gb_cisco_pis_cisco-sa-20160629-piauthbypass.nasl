###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_pis_cisco-sa-20160629-piauthbypass.nasl 11702 2018-10-01 07:31:38Z asteins $
#
# Cisco Prime Infrastructure Authentication Bypass API Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106327");
  script_version("$Revision: 11702 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-01 09:31:38 +0200 (Mon, 01 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-05 15:37:40 +0700 (Wed, 05 Oct 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-1289");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Prime Infrastructure Authentication Bypass API Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_pis_web_detect.nasl");
  script_mandatory_keys("cisco/pis/http/port");

  script_tag(name:"summary", value:"A vulnerability in the application programming interface (API) of Cisco
Prime Infrastructure could allow an unauthenticated, remote attacker to access and control the API resources.");

  script_tag(name:"insight", value:"The vulnerability is due to improper input validation of HTTP requests for
unauthenticated URIs. An attacker could exploit this vulnerability by sending a crafted HTTP request to the
affected URIs.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability could allow the attacker to
upload malicious code to the application server or read unauthorized management data, such as credentials of
devices managed by Cisco Prime Infrastructure.");

  script_tag(name:"affected", value:"Cisco Prime Infrastructure software versions 1.2 through version 3.0.");

  script_tag(name:"solution", value:"Upgrade to version 2.2.3 Update 4, 3.0.3 Update 2, or later");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160629-piauthbypass");
  script_xref(name:"URL", value:"http://www.security-assessment.com/files/documents/advisory/Cisco-Prime-Infrastructure-Release.pdf");

  script_tag(name:"vuldetect", value:"Tries to get the version over the REST API.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_kb_item("cisco/pis/http/port"))
  exit(0);

host = http_host_name(port: port);

req = 'GET /webacs/api/v1/op/info/version?_docs HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'X-HTTP-Method-Override: get\r\n' +
      'Content-Type: application/json\r\n' +
      'Connection: close\r\n' +
      'Content-Length: 0\r\n\r\n';

res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.. 200" && "<versionInfoDTO>" >< res) {
  version = eregmatch(pattern: "<result>.*</result>", string: res);
  report = "It was possible to get the version information through the REST API.\n\nResult:\n\n" + version[0] +
           "\n";
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
