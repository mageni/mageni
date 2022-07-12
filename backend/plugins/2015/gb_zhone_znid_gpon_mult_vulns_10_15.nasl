###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zhone_znid_gpon_mult_vulns_10_15.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# ZHONE ZNID GPON Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/o:zhone_technologies:gpon_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105405");
  script_version("$Revision: 12106 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-15 14:48:06 +0200 (Thu, 15 Oct 2015)");
  script_name("ZHONE ZNID GPON Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_zhone_znid_gpon_detect.nasl", "gb_zhone_znid_gpon_snmp_detect.nasl");
  script_mandatory_keys("zhone/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/536663/30/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/536666/30/0/threaded");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This vulnerability is due to the use of unsafe string functions without sufficient input validation in the httpd binary.");

  script_tag(name:"solution", value:"Upgrade to version S3.1.241");

  script_tag(name:"summary", value:"ZHONE RGW is vulnerable to stack-based buffer overflow attacks.");

  script_tag(name:"affected", value:"Model: ZHONE ZNID GPON 2426A (24xx, 24xxA, 42xx, 42xxA, 26xx, and 28xx series models) < S3.0.501");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

model = get_kb_item( "zhone/model" );

if( model !~ "^2(4|6|8)" && model !~ "^42" ) exit( 99 );

if( version_is_less( version:vers, test_version:"S3.0.501" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"S3.1.241" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
