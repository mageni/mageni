###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ucs_4_errata_137.nasl 11452 2018-09-18 11:24:16Z mmartin $
#
# Univention Corporate Server 4.0 erratum 137
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

CPE = 'cpe:/o:univention:univention_corporate_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105248");
  script_cve_id("CVE-2015-1606", "CVE-2014-3591", "CVE-2015-0837");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_version("$Revision: 11452 $");
  script_name("Univention Corporate Server 4.0 erratum 137");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 13:24:16 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-04-09 10:44:33 +0200 (Thu, 09 Apr 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ucs/errata", "ucs/version");

  script_xref(name:"URL", value:"http://errata.univention.de/ucs/4.0/137.html");

  script_tag(name:"vuldetect", value:"Checks for missing patches.");

  script_tag(name:"insight", value:"Multiple security issues have been found in GnuPG:

  * use after free when using non-standard keyring (CVE-2015-1606)

  * Side-channel attack on El-Gamal keys (CVE-2014-3591)

  * Side-channel attack in the mpi_pow() function (CVE-2015-0837)");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"The remote host is missing an update for gnupg (erratum 137)");

  script_tag(name:"affected", value:"Univention Corporate Server 4.0 erratum < 137");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) )
  if( ! version = get_kb_item("ucs/version") ) exit( 0 );

if( version !~ "^4\.0" ) exit( 0 );

if( ! errata = get_kb_item( "ucs/errata" ) ) exit( 0 );

if( int( errata ) < 137 ) {

  report = 'UCS version:           ' + version + '\n' +
           'Last installed errata: ' + errata + '\n' +
           'Fixed errata:          137\n';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
