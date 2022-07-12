###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moxa_mgate_91777.nasl 13999 2019-03-05 13:15:01Z cfischer $
#
# Moxa MGate Authentication Bypass Vulnerability
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

CPE = "cpe:/a:moxa:mgate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105823");
  script_bugtraq_id(91777);
  script_cve_id("CVE-2016-5804");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 13999 $");

  script_name("Moxa MGate Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91777");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-196-02");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass the authentication
  mechanism and perform unauthorized actions. This may lead to further attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisoryfor more information.");

  script_tag(name:"summary", value:"Moxa Multiple Products are prone to an authentication-bypass vulnerability.");

  script_tag(name:"affected", value:"The following products are affected:

  MGate MB3180, versions prior to v1.8,

  MGate MB3280, versions prior to v2.7,

  MGate MB3480, versions prior to v2.6,

  MGate MB3170, versions prior to v2.5,

  MGate MB3270, versions prior to v2.7");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2019-03-05 14:15:01 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-07-25 14:23:53 +0200 (Mon, 25 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_moxa_mgate_telnet_detect.nasl", "gb_moxa_mgate_web_detect.nasl");
  script_require_ports("Services/www", 80, "Services/telnet", 23);
  script_mandatory_keys("moxa/mgate/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ! model = get_kb_item( "moxa/mgate/model" ) )
  exit( 0 );

if( model == "MB3280" || model == "MB3270" ) fix = '2.7';
if( model == "MB3180" ) fix = '1.8';
if( model == "MB3170" ) fix = '2.5';
if( model == "MB3480" ) fix = '2.6';

if( ! fix )
  exit( 99 );

if( version_is_less( version:version, test_version:fix ) )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );