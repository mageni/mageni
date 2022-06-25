###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_mysql_old_auth_user_enum_vuln.nasl 12175 2018-10-31 06:20:00Z ckuersteiner $
#
# MySQL/MariaDB Authentication Error Message User Enumeration Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802046");
  script_version("$Revision: 12175 $");
  script_bugtraq_id(56766);
  script_cve_id("CVE-2012-5615");
  script_tag(name:"last_modification", value:"$Date: 2018-10-31 07:20:00 +0100 (Wed, 31 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-12-07 16:13:41 +0530 (Fri, 07 Dec 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("MySQL/MariaDB Authentication Error Message User Enumeration Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL_MariaDB/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51427");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/23081");
  script_xref(name:"URL", value:"https://mariadb.atlassian.net/browse/MDEV-3909");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=882608");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/12/02/3");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/12/02/4");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to obtain valid
  usernames, which may aid them in brute-force password cracking or other attacks.");

  script_tag(name:"affected", value:"MySQL version 5.5.19 and possibly other versions
  MariaDB 5.5.28a, 5.3.11, 5.2.13, 5.1.66 and possibly other versions");

  script_tag(name:"insight", value:"MySQL server will respond with a different message than Access
  Denied, when attacker authenticates using an incorrect password with the old
  authentication mechanism MySQL 4.x and below to a MySQL 5.x server.");

  script_tag(name:"solution", value:"For MariaDB upgrade to 5.5.29, 5.3.12, 5.2.14 or later.
    For MySQL apply the updates from vendor.");

  script_tag(name:"summary", value:"The host is running MySQL/MariaDB and is prone to user enumeration
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://mariadb.org/");
  script_xref(name:"URL", value:"https://www.mysql.com/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/a:mysql:mysql",
                      "cpe:/a:oracle:mysql",
                      "cpe:/a:mariadb:mariadb" );

if( ! infos = get_all_app_ports_from_list( cpe_list:cpe_list ) ) exit( 0 );
cpe = infos['cpe'];
port = infos['port'];

if( ! vers = get_app_version( cpe:cpe, port:port ) ) exit( 0 );

if( "mysql" >< cpe ) {

  if( version_is_less_equal( version:vers, test_version:"5.5.19" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
    security_message( port:port, data:report );
    exit( 0 );
  }
} else if( "mariadb" >< cpe ) {

  if( vers =~ "^5\.5\." ) {
    if( version_is_less( version:vers, test_version:"5.5.29" ) ) {
      VULN = TRUE;
      fix = "5.5.29";
    }
  }

  if( vers =~ "^5\.3\." ) {
    if( version_is_less( version:vers, test_version:"5.3.12" ) ) {
      VULN = TRUE;
      fix = "5.3.12";
    }
  }

  if( vers =~ "^5\.2\." ) {
    if( version_is_less( version:vers, test_version:"5.2.14" ) ) {
      VULN = TRUE;
      fix = "5.2.14";
    }
  }

  if( VULN ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:fix );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
