###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_hadoop_zip_slip_vuln.nasl 13054 2019-01-14 08:07:05Z asteins $
#
# Apache Hadoop before 3.1.1, 3.0.3, 2.8.5, 2.7.7 Zip Slip Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112430");
  script_version("$Revision: 13054 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-14 09:07:05 +0100 (Mon, 14 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-11-14 15:33:11 +0100 (Wed, 14 Nov 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-8009");

  script_name("Apache Hadoop before 3.1.1, 3.0.3, 2.8.5, 2.7.7 Zip Slip Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_hadoop_detect.nasl");
  script_require_ports("Services/www", 50070);
  script_mandatory_keys("Apache/Hadoop/Installed");

  script_tag(name:"summary", value:"Apache Hadoop is prone to the 'Zip Slip' Vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is exploited using a specially crafted archive that
  holds directory traversal filenames (e.g. ../../evil.sh). The Zip Slip vulnerability can affect numerous archive formats,
  including tar, jar, war, cpio, apk, rar and 7z.");

  script_tag(name:"impact", value:"Zip Slip is a form of directory traversal that can be exploited by extracting files from an archive.
  The premise of the directory traversal vulnerability is that an attacker can gain access to parts of the file system outside of the
  target folder in which they should reside. The attacker can then overwrite executable files and either invoke them remotely or wait
  for the system or user to call them, thus achieving remote command execution on the victim's machine. The vulnerability can also cause
  damage by overwriting configuration files or other sensitive resources, and can be exploited on both client (user) machines and servers.");

  script_tag(name:"affected", value:"Apache Hadoop versions 3.1.0, 3.0.0-alpha to 3.0.2, 2.9.0 to 2.9.1, 2.8.0 to 2.8.4, 2.0.0-alpha to 2.7.6, 0.23.0 to 0.23.11.");

  script_tag(name:"solution", value:"Update to version 3.1.1, 3.0.3, 2.8.5 or 2.7.7 respectively.");

  script_xref(name:"URL", value:"https://hadoop.apache.org/cve_list.html#cve-2018-8009-http-cve-mitre-org-cgi-bin-cvename-cgi-name-cve-2018-8009-zip-slip-impact-on-apache-hadoop");
  script_xref(name:"URL", value:"https://snyk.io/research/zip-slip-vulnerability");

  exit(0);
}

CPE = "cpe:/a:apache:hadoop";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "0.23.0", test_version2: "0.23.11" ) ||
    version_in_range( version: version, test_version: "2.0.0", test_version2: "2.7.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.7" );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.8.0", test_version2: "2.8.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.5" );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.9.0", test_version2: "2.9.1" ) ||
    version_in_range( version: version, test_version: "3.0.0", test_version2: "3.0.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.0.3" );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "3.1.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.1" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );