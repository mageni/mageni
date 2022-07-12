###############################################################################
# OpenVAS Vulnerability Test
# $Id: zabbix_37309.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# ZABBIX Denial Of Service and SQL Injection Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
CPE = "cpe:/a:zabbix:zabbix";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100406");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-12-17 19:46:08 +0100 (Thu, 17 Dec 2009)");
  script_cve_id("CVE-2009-4499", "CVE-2009-4501");
  script_bugtraq_id(37309);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("ZABBIX Denial Of Service and SQL Injection Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("zabbix_detect.nasl", "zabbix_web_detect.nasl"); # nb: Only the Web-GUI is providing a version but Services/zabbix is used for the port reporting
  script_require_ports("Services/www", 80, "Services/zabbix", 10050, 10051);
  script_mandatory_keys("Zabbix/Web/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37740/");
  script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-1031");
  script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-1355");
  script_xref(name:"URL", value:"http://www.zabbix.com/index.php");

  script_tag(name:"summary", value:"ZABBIX is prone to a denial-of-service vulnerability and an SQL-
  injection vulnerability.");

  script_tag(name:"impact", value:"Successful exploits may allow remote attackers to crash the affected
  application, exploit latent vulnerabilities in the underlying database, access or modify data, or
  compromise the application.");

  script_tag(name:"affected", value:"Versions prior to ZABBIX 1.6.8 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 ); # nb: Only the Web-GUI is providing a version

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"1.6.8" ) ) {
  if( zabbix_port = get_kb_item( "Services/zabbix" ) ) {
    port = zabbix_port;
  }
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.6.8" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );