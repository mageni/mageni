###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zabbix_42017.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# ZABBIX 'formatQuery()' Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100729");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-08-02 14:28:14 +0200 (Mon, 02 Aug 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-2790");
  script_bugtraq_id(42017);
  script_name("ZABBIX 'formatQuery()' Cross Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("zabbix_web_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Zabbix/Web/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42017");
  script_xref(name:"URL", value:"http://www.zabbix.org");
  script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-2326");

  script_tag(name:"summary", value:"ZABBIX is prone to a cross-site scripting vulnerability
  because it fails to properly sanitize user-supplied input.");
  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may allow the attacker to steal cookie-based authentication
  credentials and to launch other attacks.");
  script_tag(name:"affected", value:"ZABBIX version 1.8.2 is vulnerable, other versions may also be
  affected.");
  script_tag(name:"solution", value:"Updates are available. Please see the reference for more details.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"1.8.0", test_version2:"1.8.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.8.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );
