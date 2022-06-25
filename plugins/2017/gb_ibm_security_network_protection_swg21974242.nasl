###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_security_network_protection_swg21974242.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# IBM Security Network Protection Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:ibm:security_network_protection";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140117");
  script_version("$Revision: 12106 $");
  script_name("IBM Security Network Protection Information Disclosure Vulnerability");
  script_cve_id("CVE-2016-0201");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21974242");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"IBM GSKit could allow a remote attacker to obtain sensitive information, caused by a MD5 collision. An attacker could exploit this vulnerability to obtain authentication credentials.");
  script_tag(name:"solution", value:"Update to 5.3.1.7/5.3.2.1 or newer");
  script_tag(name:"summary", value:"A vulnerability has been addressed in the GSKit component of IBM Security Network Protection.");

  script_tag(name:"affected", value:"IBM Security Network Protection 5.3.1
IBM Security Network Protection 5.3.2");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-10 09:29:08 +0100 (Tue, 10 Jan 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_security_network_protection_version.nasl");
  script_mandatory_keys("isnp/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version =~ "^5\.3\.1" )
  if( version_is_less( version:version, test_version:"5.3.1.6" ) ) fix = "5.3.1.7";

if( version =~ "^5\.3\.2" )
  if( version_is_less( version:version, test_version:"5.3.2.0" ) ) fix = "5.3.2.1";

if( fix )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

