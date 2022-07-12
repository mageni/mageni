###############################################################################
# OpenVAS Vulnerability Test
#
# PHP Multiple Vulnerabilities May18 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813159");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-10549", "CVE-2018-10546", "CVE-2018-10548", "CVE-2018-10547");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-02 17:42:59 +0530 (Wed, 02 May 2018)");
  script_name("PHP Multiple Vulnerabilities May18 (Windows)");

  script_tag(name:"summary", value:"The host is installed with php and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to

  - An out of bounds read error in 'exif_read_data' function while processing
    crafted JPG data.

  - An error in stream filter 'convert.iconv' which leads to infinite loop on
    invalid sequence.

  - An error in the LDAP module of PHP which allows a malicious LDAP server or
    man-in-the-middle attacker to crash PHP.

  - An error in the 'phar_do_404()' function in 'ext/phar/phar_object.c' script
    which returns parts of the request unfiltered, leading to another XSS vector.
    This is due to incomplete fix for CVE-2018-5712.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct XSS attacks, crash PHP, conduct denial-of-service condition and
  execute arbitrary code in the context of the affected application.");

  script_tag(name:"affected", value:"PHP versions prior to 5.6.36,

  PHP versions 7.2.x prior to 7.2.5,

  PHP versions 7.0.x prior to 7.0.30,

  PHP versions 7.1.x prior to 7.1.17 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 7.2.5 or 7.0.30 or
  5.6.36 or 7.1.17 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php#5.6.36");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php#7.0.30");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php#7.1.17");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php#7.2.5");

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(phport = get_app_port(cpe: CPE))){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:phport, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_in_range(version: vers, test_version: "7.2", test_version2: "7.2.4")){
  fix = "7.2.5";
}
else if(version_in_range(version: vers, test_version: "7.0", test_version2: "7.0.29")){
  fix = "7.0.30";
}
else if(version_in_range(version: vers, test_version: "7.1", test_version2: "7.1.16")){
  fix = "7.1.17";
}
else if(version_is_less(version: vers, test_version: "5.6.36")){
  fix = "5.6.36";
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:phport, data:report);
  exit(0);
}
exit(0);
