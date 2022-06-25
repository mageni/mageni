###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Multiple Vulnerabilities (Security Release) - December 2018 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.112466");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-12-17 14:16:22 +0100 (Mon, 17 Dec 2018)");

  script_name("WordPress Multiple Vulnerabilities (Security Release) - December 2018 (Linux)");

  script_cve_id("CVE-2018-20147", "CVE-2018-20148", "CVE-2018-20149", "CVE-2018-20150", "CVE-2018-20151", "CVE-2018-20152", "CVE-2018-20153");
  script_bugtraq_id(106220);

  script_tag(name:"summary", value:"This host is running WordPress and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Authors could alter meta data to delete files that they weren't authorized to.

  - Authors could create posts of unauthorized post types with specially crafted input.

  - Contributors could craft meta data in a way that resulted in PHP object injection.

  - Contributors could edit new comments from higher-privileged users, potentially leading to a cross-site scripting vulnerability.

  - Specially crafted URL inputs could lead to a cross-site scripting vulnerability in some circumstances.
  WordPress itself was not affected, but plugins could be in some situations.

  - The user activation screen could be indexed by search engines in some uncommon configurations,
  leading to exposure of email addresses, and in some rare cases, default generated passwords.

  - Authors on Apache-hosted sites could upload specifically crafted files that bypass MIME verification,
  leading to a cross-site scripting vulnerability.");

  script_tag(name:"affected", value:"All versions since WordPress 3.7 up to 5.0.");

  script_tag(name:"solution", value:"The issues have been fixed in version 5.0.1.
  Updated versions of WordPress 4.9 and older releases are also available.

  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/");
  script_xref(name:"URL", value:"https://wordpress.org/download/releases/");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) {
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_equal(version:vers, test_version:"5.0.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.0.1", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:vers, test_version:"4.9.0", test_version2:"4.9.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.9.9", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:vers, test_version:"4.8.0", test_version2:"4.8.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.8.8", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:vers, test_version:"4.7.0", test_version2:"4.7.11")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.7.12", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:vers, test_version:"4.6.0", test_version2:"4.6.12")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.6.13", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:vers, test_version:"4.5.0", test_version2:"4.5.15")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.5.16", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:vers, test_version:"4.4.0", test_version2:"4.4.16")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.4.17", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:vers, test_version:"4.3.0", test_version2:"4.3.17")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.3.18", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:vers, test_version:"4.2.0", test_version2:"4.2.21")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.2.22", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:vers, test_version:"4.1.0", test_version2:"4.1.24")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.1.25", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:vers, test_version:"4.0.0", test_version2:"4.0.24")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.0.25", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:vers, test_version:"3.9.0", test_version2:"3.9.25")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.9.26", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:vers, test_version:"3.8.0", test_version2:"3.8.27")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.8.28", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_is_less(version:vers, test_version:"3.7.28")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.7.28", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
