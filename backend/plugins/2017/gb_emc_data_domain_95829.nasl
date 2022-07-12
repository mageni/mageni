###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emc_data_domain_95829.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# EMC Data Domain OS Local Command Injection Vulnerability
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

CPE = "cpe:/a:emc:data_domain_os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140144");
  script_bugtraq_id(95829);
  script_cve_id("CVE-2016-8216");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_version("$Revision: 12106 $");

  script_name("EMC Data Domain OS Local Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95829");
  script_xref(name:"URL", value:"http://www.emc.com/");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2017/Jan/att-79/ESA-2016-160.txt");

  script_tag(name:"impact", value:"A local attacker can exploit this issue to bypass the Data Domain restricted shell (ddsh) to gain shell access and execute arbitrary commands with root privileges.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"The following EMC Data Domain OS (DD OS) release contains a resolution to this vulnerability:
EMC Data Domain DD OS 5.7 family version 5.7.2.10 and later
EMC Data Domain DD OS 5.6 family version 5.6.2.0  and later
EMC Data Domain DD OS 5.5 family version 5.5.5.0 and late");
  script_tag(name:"summary", value:"EMC Data Domain OS is prone to a local command-injection vulnerability.");
  script_tag(name:"affected", value:"EMC Data Domain OS (DD OS) 5.4 all versions
EMC Data Domain OS (DD OS) 5.5 family all versions prior to 5.5.5.0
EMC Data Domain OS (DD OS) 5.6 family all versions prior to 5.6.2.0
EMC Data Domain OS (DD OS) 5.7 family all versions prior to 5.7.2.10");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-01 14:29:24 +0100 (Wed, 01 Feb 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_emc_data_domain_version.nasl");
  script_mandatory_keys("emc/data_domain/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version =  get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version =~ "^5\.5" )
  fix = '5.5.5.0';

else if( version =~ "^5\.6" )
  fix = '5.6.2.0';

else if( version =~ "^5\.7" )
  fix = '5.7.2.10';

if( ! fix ) exit( 99 );

if( version_is_less( version:version, test_version:fix ) )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix);
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

