###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_core_mult_vuln_SA-CORE-2018-006_lin.nasl 12041 2018-10-23 13:56:19Z cfischer $
#
# Drupal Core Multiple Security Vulnerabilities (SA-CORE-2018-006) (Linux)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112394");
  script_version("$Revision: 12041 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 15:56:19 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-22 10:05:23 +0200 (Mon, 22 Oct 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Drupal Core Multiple Security Vulnerabilities (SA-CORE-2018-006) (Linux)");

  script_tag(name:"summary", value:"This host is running Drupal and is prone
  to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Drupal is prone to the following vulnerabilities:

  - In some conditions, content moderation fails to check a
  users access to use certain transitions, leading to an access bypass.

  - The path module allows users with the 'administer paths' to create pretty URLs for content.
  In certain circumstances the user can enter a particular path that triggers an open redirect to a malicious url.

  - Drupal core and contributed modules frequently use a 'destination' query string parameter
  in URLs to redirect users to a new destination after completing an action on the current page.
  Under certain circumstances, malicious users can use this parameter to construct a URL that will
  trick users into being redirected to a 3rd party website, thereby exposing the users to potential
  social engineering attacks.

  - When sending email some variables were not being sanitized for shell arguments,
  which could lead to remote code execution.

  - The Contextual Links module doesn't sufficiently validate the requested contextual links.
  This vulnerability is mitigated by the fact that an attacker must have a role with the permission 'access contextual links'.");

  script_tag(name:"affected", value:"Drupal core versions 7.x before 7.60, 8.5.x before 8.5.8 and 8.6.x before 8.6.2 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Drupal core version 7.60, 8.5.8 or 8.6.2 respectively.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2018-006");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

CPE = 'cpe:/a:drupal:drupal';

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, version_regex:"^[0-9]\.[0-9]+", exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.59")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.60", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:vers, test_version:"8.5.0", test_version2:"8.5.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.5.8", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:vers, test_version:"8.6.0", test_version2:"8.6.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.6.2", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
