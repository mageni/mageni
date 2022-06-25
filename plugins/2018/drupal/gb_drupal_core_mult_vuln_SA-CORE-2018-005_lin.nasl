###############################################################################
# OpenVAS Vulnerability Test
#
# Drupal Core Multiple Security Vulnerabilities (SA-CORE-2018-005) (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813739");
  script_version("2019-05-03T13:51:56+0000");
  script_cve_id("CVE-2018-14773");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 13:51:56 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-03 12:05:43 +0530 (Fri, 03 Aug 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Drupal Core Multiple Security Vulnerabilities (SA-CORE-2018-005) (Linux)");

  script_tag(name:"summary", value:"This host is running Drupal and is prone
  to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to multiple errors
  in 3rd party libraries 'Symfony', 'zend-diactoros' and 'zend-feed' which are
  used in drupal. In each case, vulnerability let users override the path in the
  request URL via the X-Original-URL or X-Rewrite-URL HTTP request header which
  can allow a user to access one URL but have application return a different one.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass security restrictions and emulate the headers to request
  arbitrary content.");

  script_tag(name:"affected", value:"Drupal core versions 8.x before 8.5.6 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Drupal core version 8.5.6 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2018-005");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2018-14773-remove-support-for-legacy-and-risky-http-headers");
  script_xref(name:"URL", value:"https://framework.zend.com/security/advisory/ZF2018-01");
  script_xref(name:"URL", value:"https://www.drupal.org");

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

if(version_in_range(version:drupalVer, test_version:"8.0", test_version2:"8.5.5")) {
  report = report_fixed_ver(installed_version:drupalVer, fixed_version:"8.5.6", install_path:path);
  security_message(data:report, port:drupalPort);
  exit(0);
}

exit(99);
