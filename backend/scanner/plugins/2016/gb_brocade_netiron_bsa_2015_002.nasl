###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_brocade_netiron_bsa_2015_002.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Brocade Security Advisory BSA-2015-002 (NTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.140060");
  script_cve_id("CVE-2014-9296");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 12051 $");

  script_name("Brocade Security Advisory BSA-2015-002 (NTP)");

  script_xref(name:"URL", value:"http://www.brocade.com/en/backend-content/pdf-page.html?/content/dam/common/documents/content-types/security-bulletin/brocade-assessment-ntp-vu-852879-vulnerability.pdf");

  script_tag(name:"summary", value:"The receive function in ntp_proto.c in ntpd in NTP before 4.2.8 continues to execute after detecting a certain authentication error, which might allow remote attackers to trigger an unintended association change via crafted packets");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Fixed in 5.6.00f, 5.7.00d, 5.8.00a, 5.9.00");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-14 18:47:10 +0100 (Mon, 14 Nov 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_brocade_netiron_snmp_detect.nasl");
  script_mandatory_keys("brocade_netiron/os/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

fix = FALSE;

if( version =~ "^5\.9\.0" ) exit( 99 );

if( version =~ "^5\.6\.0" )
  if( revcomp( a:version, b:"5.6.0e" ) <= 0 )  fix = '5.6.00f';

if( version =~ "^5\.7\.0" )
  if( revcomp( a:version, b:"5.7.0c" ) <= 0 )  fix = '5.7.00d';

if( version == "5.8.0" )
  fix = '5.8.0a';

if( fix )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

