##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_isc_bind_nsec3_signed_dos_vuln.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# ISC BIND NSEC3 Signed Zones Queries Denial of Service Vulnerability - Jan16
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807216");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2014-0591");
  script_bugtraq_id(64801);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-01-28 12:39:11 +0530 (Thu, 28 Jan 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND NSEC3 Signed Zones Queries Denial of Service Vulnerability - Jan16");

  script_tag(name:"summary", value:"The host is installed with ISC BIND and is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  'query_findclosestnsec3' function in 'query.c' script in ISC BIND.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service.");

  script_tag(name:"affected", value:"ISC BIND versions 9.6.0.x through 9.6-ESV-R10-P1,
  9.7 (all versions), 9.8.0 through 9.8.6-P1, 9.9.0 through 9.9.4-P1.");

  script_tag(name:"solution", value:"Upgrade to ISC BIND version 9.6-ESV-R10-P2
  or 9.8.6-P2 or 9.9.4-P2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01078");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("bind_version.nasl");
  script_mandatory_keys("ISC BIND/installed");
  script_xref(name:"URL", value:"https://www.isc.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! bindPort = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:bindPort ) ) exit( 0 );

bindVer = infos["version"];
proto = infos["proto"];

if(version_in_range(version:bindVer, test_version:"9.6.0", test_version2:"9.6.ESV.R10.P1"))
{
  fix = "9.6-ESV-R10-P2";
  VULN = TRUE;
}

else if(version_in_range(version:bindVer, test_version:"9.7.0", test_version2:"9.8.6.P1"))
{
  fix = "9.8.6-P2";
  VULN = TRUE;
}

else if(version_in_range(version:bindVer, test_version:"9.9.0", test_version2:"9.9.4.P1"))
{
  fix ="9.9.4-P2";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:bindVer, fixed_version:fix);
  security_message( data:report, port:bindPort, proto:proto );
  exit( 0 );
}

exit( 99 );