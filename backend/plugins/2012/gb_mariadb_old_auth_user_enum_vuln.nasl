###############################################################################
# OpenVAS Vulnerability Test
#
# MySQL/MariaDB Authentication Error Message User Enumeration Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mariadb:mariadb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802046");
  script_version("2021-02-10T15:50:32+0000");
  script_bugtraq_id(56766);
  script_cve_id("CVE-2012-5615");
  script_tag(name:"last_modification", value:"2021-02-12 11:04:26 +0000 (Fri, 12 Feb 2021)");
  script_tag(name:"creation_date", value:"2012-12-07 16:13:41 +0530 (Fri, 07 Dec 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("MariaDB Authentication Error Message User Enumeration Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl");
  script_mandatory_keys("mariadb/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51427");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/23081");
  script_xref(name:"URL", value:"https://mariadb.atlassian.net/browse/MDEV-3909");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=882608");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/12/02/3");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/12/02/4");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to obtain valid
  usernames, which may aid them in brute-force password cracking or other attacks.");

  script_tag(name:"affected", value:"MariaDB 5.5.28a, 5.3.11, 5.2.13, 5.1.66 and possibly other versions.");

  script_tag(name:"insight", value:"A MariaDB server will respond with a different message than Access
  Denied, when an attacker authenticates using an incorrect password with the old authentication mechanism
  from MySQL 4.x and below (as used in MariaDB) to a MariaDB 5.x server.");

  script_tag(name:"solution", value:"Update MariaDB to version 5.5.29, 5.3.12, 5.2.14 or later.");

  script_tag(name:"summary", value:"MariaDB is prone to a user enumeration vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( vers =~ "^5\.5\." && version_is_less( version:vers, test_version:"5.5.29" ) )
  fix = "5.5.29";

else if( vers =~ "^5\.3\." && version_is_less( version:vers, test_version:"5.3.12" ) )
  fix = "5.3.12";

else if( vers =~ "^5\.2\." && version_is_less( version:vers, test_version:"5.2.14" ) )
  fix = "5.2.14";

if( fix ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix, install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );