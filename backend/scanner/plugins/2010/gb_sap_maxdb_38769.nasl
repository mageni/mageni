###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sap_maxdb_38769.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# SAP MaxDB 'serv.exe' Unspecified Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:sap:maxdb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100541");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-17 21:52:47 +0100 (Wed, 17 Mar 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-1185");
  script_bugtraq_id(38769);
  script_name("SAP MaxDB 'serv.exe' Unspecified Remote Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_sap_maxdb_detect.nasl");
  script_require_ports("Services/sap_maxdb", 7210);
  script_mandatory_keys("sap_maxdb/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38769");
  script_xref(name:"URL", value:"https://www.sdn.sap.com/irj/sdn/maxdb");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-032/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/510125");
  script_xref(name:"URL", value:"https://websmp202.sap-ag.de/sap/support/notes/1409425");

  script_tag(name:"solution", value:"Vendor updates are available through SAP note 1409425. Please contact the vendor for more information.");

  script_tag(name:"summary", value:"SAP MaxDB is prone to an unspecified remote code-execution
  vulnerability because it fails to sufficiently validate user-supplied input.");

  script_tag(name:"impact", value:"An attacker can leverage this issue to execute arbitrary code with
  SYSTEM-level privileges. Failed exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! ver = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( ! version = get_kb_item( "sap_maxdb/" + port + "/version" ) ) exit( 0 );
if( ! build   = get_kb_item( "sap_maxdb/" + port + "/build" ) ) exit( 0 );
build = ereg_replace( pattern:"^([0-9]+)\-[0-9]+\-[0-9]+\-[0-9]+$", string:build, replace:"\1" );

maxdb_version = version + "." + build;

if( version_is_equal( version:maxdb_version, test_version:"7.6.6" )     ||
    version_is_equal( version:maxdb_version, test_version:"7.6.3.007" ) ||
    version_is_equal( version:maxdb_version, test_version:"7.6.03.15" ) ||
    version_is_equal( version:maxdb_version, test_version:"7.6.00.37" ) ||
    version_is_equal( version:maxdb_version, test_version:"7.6.0.37" )  ||
    version_is_equal( version:maxdb_version, test_version:"7.4.3.32" ) ) {
  report = report_fixed_ver( installed_version:maxdb_version, fixed_version:"See SAP note 1409425" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );