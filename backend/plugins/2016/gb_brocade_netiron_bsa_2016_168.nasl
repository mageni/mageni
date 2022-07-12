###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_brocade_netiron_bsa_2016_168.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# Brocade Security Advisory BSA-2016-168 (Memory Corruption Vulnerability)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = 'cpe:/o:brocade:netiron_os';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140059");
  script_cve_id("CVE-2016-8203");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12363 $");

  script_name("Brocade Security Advisory BSA-2016-168 (Memory Corruption Vulnerability)");

  script_xref(name:"URL", value:"http://www.brocade.com/en/backend-content/pdf-page.html?/content/dam/common/documents/content-types/security-bulletin/brocade-security-advisory-2016-168.pdf");

  script_tag(name:"summary", value:"A memory corruption in the IPsec code path of Brocade NetIron OS on Brocade MLXs 5.8.00 through 5.8.00e, 5.9.00 through 5.9.00bd, 6.0.00 and 6.0.00a images could allow attackers to causse a denial of service (line card reset) via certain constructed IPsec control packets");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Brocade has fixed the vulnerability described in this advisory in NetIron 5.8.00ec, 5.9.00be and 6.0.00ab and later releases.");

  script_tag(name:"affected", value:"Brocade NetIron OS on Brocade MLXs 5.8.00 through 5.8.00e, 5.9.00 through 5.9.00bd, 6.0.00 and 6.0.00a images.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-14 18:46:10 +0100 (Mon, 14 Nov 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_brocade_netiron_snmp_detect.nasl");
  script_mandatory_keys("brocade_netiron/os/version", "brocade_netiron/typ");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

t = get_kb_item( "brocade_netiron/typ" );

if( "MLX" >!< t ) exit( 99 );

fix = FALSE;

if( version =~ "^5\.8\.0" )
  if( revcomp( a:version, b:"5.8.0e" ) <= 0 )  fix = '5.8.00ec';

if( version =~ "^5\.9\.0" )
  if( revcomp( a:version, b:"5.9.0bd" ) <= 0 ) fix = '5.9.00be';

if( version =~ "^6\.0\.0" )
  if( revcomp( a:version, b:"6.0.0a" ) <= 0 )  fix = '6.0.00ab';

if( fix )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

