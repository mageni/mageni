###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_core_mult_vuln_SA-CORE-2018-001_lin.nasl 12012 2018-10-22 09:20:29Z asteins $
#
# Drupal Core Multiple Vulnerabilities (SA-CORE-2018-001) (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = 'cpe:/a:drupal:drupal';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812776");
  script_version("$Revision: 12012 $");
  script_cve_id("CVE-2017-6926", "CVE-2017-6927", "CVE-2017-6928",
  "CVE-2017-6929", "CVE-2017-6930", "CVE-2017-6931", "CVE-2017-6932");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 11:20:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-22 10:43:18 +0530 (Thu, 22 Feb 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Drupal Core Multiple Vulnerabilities (SA-CORE-2018-001) (Linux)");

  script_tag(name:"summary", value:"This host is running Drupal and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An improper access restriction for sensitive contents via 'Comment reply form'.

  - 'Drupal.checkPlain' JavaScript function does not correctly handle all methods
    of injecting malicious HTML.

  - Private file access check fails under certain conditions in which one module
    is trying to grant access to the file and another is trying to deny it.

  - A jQuery cross site scripting vulnerability is present when making Ajax
    requests to untrusted domains.

  - Language fallback can be incorrect on multilingual sites with node access
    restrictions.

  - An error in 'Settings Tray module'.

  - An external link injection vulnerability when the language switcher block
    is used.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to trick users into unwillingly navigating to an external site,
  update certain data that they do not have the permissions for, execute
  arbitrary script and gain extra privileges.");

  script_tag(name:"affected", value:"Drupal core version 8.x versions prior to
  8.4.5 and 7.x versions prior to 7.57 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Drupal core version 8.4.5 or
  7.57 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2018-001");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!drupalPort = get_app_port(cpe:CPE)) {
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:drupalPort, version_regex:"^[0-9]\.[0-9]+", exit_no_version:TRUE)) {
  exit(0);
}

drupalVer = infos['version'];
path = infos['location'];

if(drupalVer =~ "^(8\.)" && version_is_less(version:drupalVer, test_version:"8.4.5")) {
  fix = "8.4.5";
}

if(drupalVer =~ "^(7\.)" && version_is_less(version:drupalVer, test_version:"7.57")) {
  fix = "7.57";
}

if(fix) {
  report = report_fixed_ver(installed_version:drupalVer, fixed_version:fix, install_path:path);
  security_message(data:report, port:drupalPort);
  exit(0);
}

exit(99);
