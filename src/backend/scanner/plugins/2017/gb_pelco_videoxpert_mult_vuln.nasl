###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pelco_videoxpert_mult_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Pelco VideoXpert Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:pelco:videoxpert";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106936");
  script_version("$Revision: 11874 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-11 09:20:39 +0700 (Tue, 11 Jul 2017)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2017-9964", "CVE-2017-9965", "CVE-2017-9966");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pelco VideoXpert Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pelco_videoxpert_detect.nasl");
  script_mandatory_keys("pelco_videoxpert/installed");

  script_tag(name:"summary", value:"Pelco VideoXpert is prone to multiple vulnerabilities:

  - Directory traversal vulnerability which allows unauthenticated attackers to read arbitrary files in the context
of the web server. (CVE-2017-9965)

  - Missing encryption of sensitive information. The software transmits sensitive data using double Base64 encoding
for the Cookie 'auth_token' in a communication channel that can be sniffed by unauthorized actors or arbitrarely
be read from the vxcore log file directly using directory traversal attack resulting in authentication bypass/
session hijacking. (CVE-2017-9964)

  - By replacing certain files, an authorized user can obtain system privileges and the inserted code would execute
at an elevated privilege level. (CVE-2017-9966)");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"Update to version 2.1 or later.");

  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5419.php");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5420.php");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-355-02");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

url = "/portal//..\\\..\\\..\\\..\\\windows\win.ini";

if (http_vuln_check(port: port, url: url, pattern: "; for 16-bit app support", check_header: TRUE)) {
  report = "It was possible to obtain the 'win.ini' file through a path traversal exploit.";
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
