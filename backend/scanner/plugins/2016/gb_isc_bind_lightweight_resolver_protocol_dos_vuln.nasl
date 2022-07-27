###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_isc_bind_lightweight_resolver_protocol_dos_vuln.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# ISC BIND 'lightweight resolver protocol' Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.808751");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-2775");
  script_bugtraq_id(92037);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-08-05 18:16:09 +0530 (Fri, 05 Aug 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND 'lightweight resolver protocol' Denial of Service Vulnerability");

  script_tag(name:"summary", value:"The host is installed with ISC BIND and is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in the BIND
  implementation of the lightweight resolver protocol which use alternate method
  to do name resolution.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service.");

  script_tag(name:"affected", value:"ISC BIND versions 9.0.x through 9.9.9-P1,
  9.10.0 through 9.10.4-P1, 9.11.0a3 through 9.11.0b1.");

  script_tag(name:"solution", value:"Upgrade to ISC BIND version 9.9.9-P2 or
  9.10.4-P2 or 9.11.0b2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01393/74/CVE-2016-2775");

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

if(version_in_range(version:bindVer, test_version:"9.0", test_version2:"9.9.9.P1"))
{
  fix = "9.9.9-P2";
  VULN = TRUE;
}
else if(version_in_range(version:bindVer, test_version:"9.10.0", test_version2:"9.10.4.P1"))
{
  fix = "9.10.4-P2";
  VULN = TRUE;
}
else if(version_in_range(version:bindVer, test_version:"9.11.0a3", test_version2:"9.11.0b1"))
{
  fix = "9.11.0b2";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:bindVer, fixed_version:fix);
  security_message( data:report, port:bindPort, proto:proto );
  exit( 0 );
}

exit( 99 );