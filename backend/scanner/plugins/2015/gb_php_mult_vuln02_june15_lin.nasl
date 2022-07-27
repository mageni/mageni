###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_vuln02_june15_lin.nasl 2015-06-16 18:45:49 Jun$
#
# PHP Multiple Vulnerabilities - 02 - Jun15 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805660");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-4026", "CVE-2015-4025", "CVE-2015-4024", "CVE-2015-4022",
                "CVE-2015-4021");
  script_bugtraq_id(75056, 74904, 74903, 74902, 74700);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-16 18:45:49 +0530 (Tue, 16 Jun 2015)");
  script_name("PHP Multiple Vulnerabilities - 02 - Jun15 (Linux)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Algorithmic complexity vulnerability in the 'multipart_buffer_headers'
    function in main/rfc1867.c script in PHP.

  - 'pcntl_exec' implementation in PHP truncates a pathname upon encountering a
    \x00 character.

  - Integer overflow in the 'ftp_genlist' function in ext/ftp/ftp.c script in PHP.

  - The 'phar_parse_tarfile' function in ext/phar/tar.c script in PHP does not
    verify that the first character of a filename is different from the
    \0 character.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service, bypass intended extension
  restrictions and access  and execute files or directories with unexpected
  names via crafted dimensions and remote FTP servers to execute arbitrary code.");

  script_tag(name:"affected", value:"PHP versions before 5.4.41, 5.5.x before
  5.5.25, and 5.6.x before 5.6.9");

  script_tag(name:"solution", value:"Upgrade to PHP 5.4.41 or 5.5.25 or 5.6.9
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=69085");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/06/01/4");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_unixoide");
  script_xref(name:"URL", value:"http://www.php.net");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(phpVer =~ "^5\.5")
{
  if(version_in_range(version:phpVer, test_version:"5.5.0", test_version2:"5.5.24"))
  {
    fix = "5.5.25";
    VULN = TRUE;
  }
}

if(phpVer =~ "^5\.6")
{
  if(version_in_range(version:phpVer, test_version:"5.6.0", test_version2:"5.6.8"))
  {
    fix = "5.6.9";
    VULN = TRUE;
  }
}

if(phpVer =~ "^5\.4")
{
  if(version_is_less(version:phpVer, test_version:"5.4.41"))
  {
    fix = "5.4.41";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = 'Installed Version: ' + phpVer + '\n' +
           'Fixed Version:     ' + fix + '\n';
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);