##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_peplink_balance_mult_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Peplink Balance Routers Multiple Vulnerabilities
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

CPE = "cpe:/a:peplink:balance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106848");
  script_version("$Revision: 11863 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-06 10:51:07 +0700 (Tue, 06 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-8835", "CVE-2017-8836", "CVE-2017-8837", "CVE-2017-8838", "CVE-2017-8839",
                "CVE-2017-8840", "CVE-2017-8841");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Peplink Balance Routers Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_peplink_balance_webadmin_detect.nasl");
  script_mandatory_keys("peplink_balance/detected");

  script_tag(name:"summary", value:"Peplink Balance routers are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Peplink Balance routers are prone to multiple vulnerabilities:

  - SQL injection attack via the 'bauth' cookie parameter (CVE-2017-8835)

  - No CSRF Protection (CVE-2017-8836)

  - Passwords stored in Cleartext (CVE-2017-8837)

  - XSS via syncid Parameter (CVE-2017-8838)

  - XSS via preview.cgi (CVE-2017-8839)

  - File Deletion (CVE-2017-8841)

  - Information Disclosure (CVE-2017-8840)");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP request and checks the response.");

  script_tag(name:"affected", value:"Peplink Balance Router firmware 7.0.0-build1904 and possible prior.");

  script_tag(name:"solution", value:"Update to firmware version 7.0.1-build2093 or later.");

  script_xref(name:"URL", value:"https://www.x41-dsec.de/lab/advisories/x41-2017-005-peplink/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

url = '/cgi-bin/HASync/hasync.cgi?debug=1';

if (http_vuln_check(port: port, url: url, pattern: "Master LAN Address", check_header: TRUE,
                    extra_check: "HA Group ID")) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
