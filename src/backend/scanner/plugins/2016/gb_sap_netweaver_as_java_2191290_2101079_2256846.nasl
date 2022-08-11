# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:sap:netweaver_application_server_java";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106083");
  script_version("2021-04-13T08:10:01+0000");
  script_tag(name:"last_modification", value:"2021-04-13 10:12:16 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"creation_date", value:"2016-05-23 10:42:10 +0700 (Mon, 23 May 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-1910", "CVE-2016-2386", "CVE-2016-2388");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SAP NetWeaver AS Java Multiple Vulnerabilities (2101079, 2191290, 2256846)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_sap_netweaver_as_java_http_detect.nasl");
  script_mandatory_keys("sap/netweaver_as_java/http/detected");

  script_tag(name:"summary", value:"SAP NetWeaver Application Server (AS) Java is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2016-1910: The User Management Engine (UME) allows attackers to decrypt unspecified data via
  unknown vectors.

  - CVE-2016-2386: SQL injection vulnerability in the UDDI server.

  - CVE-2016-2388: The Universal Worklist Configuration allows remote attackers to obtain sensitive
  user information via a crafted HTTP request.");

  script_tag(name:"impact", value:"A remote attacker may execute arbitrary SQL commands or obtain
  sensitive user information via a crafted HTTP request.");

  script_tag(name:"affected", value:"SAP NetWeaver AS Java version 7.10 (7.1) through 7.50 (7.5).");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://service.sap.com/sap/support/notes/2101079");
  script_xref(name:"URL", value:"https://service.sap.com/sap/support/notes/2191290");
  script_xref(name:"URL", value:"https://service.sap.com/sap/support/notes/2256846");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39841/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43495/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/webdynpro/resources/sap.com/tc~rtc~coll.appl.rtc~wd_chat/Chat";

# NetWeaver seems sometimes to check the 'User-Agent'
req = http_get_req(port: port, url: url, user_agent: "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.19) Gecko/20110420 Firefox/3.5.19");
res = http_keepalive_send_recv(port: port, data: req);

if ("Add Participant" >< res && "<title>Instant Messaging</title>" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);