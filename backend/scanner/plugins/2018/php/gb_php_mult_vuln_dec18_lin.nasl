###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_vuln_dec18_lin.nasl 13857 2019-02-26 03:40:29Z ckuersteiner $
#
# PHP Multiple Vulnerabilities - Dec19 (Linux)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108507");
  script_version("2019-03-29T15:39:23+0000");
  script_cve_id("CVE-2018-19518", "CVE-2018-20783", "CVE-2018-19396");
  script_bugtraq_id(106018);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-03-29 15:39:23 +0000 (Fri, 29 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-12-11 09:08:47 +0100 (Tue, 11 Dec 2018)");
  script_name("PHP Multiple Vulnerabilities - Dec18 (Linux)");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=76428");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77153");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77160");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77143");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/106018");
  script_xref(name:"URL", value:"https://github.com/Bo0oM/PHP_imap_open_exploit/blob/master/exploit.php");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/45914/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2018/11/22/3");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist due to,

  - the imap_open functions which allows to run arbitrary shell commands via mailbox parameter.

  - a Heap Buffer Overflow (READ: 4) in phar_parse_pharfile.

  - ext/standard/var_unserializer.c allows attackers to cause a denial of service (application crash)
  via an unserialize call for the com, dotnet, or variant class.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute remote code on the affected application/system and/or
  cause a cause a denial of service.");

  script_tag(name:"affected", value:"PHP versions 5.x before 5.6.39, 7.0.x before 7.0.33, 7.1.x before 7.1.25
  and 7.2.x before 7.2.13.");

  script_tag(name:"solution", value:"Update to version 5.6.39, 7.0.33, 7.1.25, 7.2.13, 7.3.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( version_in_range( version:vers, test_version:"5.0.0", test_version2:"5.6.38" ) ) {
  fix = "5.6.39";
} else if( version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.32" ) ) {
  fix = "7.0.33";
} else if( version_in_range( version:vers, test_version:"7.1.0", test_version2:"7.1.24" ) ) {
  fix = "7.1.25";
} else if( version_in_range( version:vers, test_version:"7.2.0", test_version2:"7.2.12" ) ) {
  fix = "7.2.13";
}

if( fix ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix, install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );