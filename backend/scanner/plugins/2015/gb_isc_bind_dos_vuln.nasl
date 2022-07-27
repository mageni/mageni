###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_isc_bind_dos_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# ISC BIND Denial of Service Vulnerability - Oct15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806079");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-4620");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-07 15:17:54 +0530 (Wed, 07 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND Denial of Service Vulnerability - Oct15");

  script_tag(name:"summary", value:"The host is installed with ISC BIND and is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'name.c'
  script in ISC BIND when configured as a recursive resolver with DNSSEC
  validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause denial of service to clients.");

  script_tag(name:"affected", value:"ISC BIND versions 9.7.x through 9.9.x before
  9.9.7-P1 and 9.10.x before 9.10.2-P2");

  script_tag(name:"solution", value:"Upgrade to ISC BIND version 9.9.7-P1 or
  9.10.2-P2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01267");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(version_in_range(version:bindVer, test_version:"9.7.0", test_version2:"9.9.7"))
{
  fix = "9.9.7-P1";
  VULN = TRUE;
}

if(version_in_range(version:bindVer, test_version:"9.10.0", test_version2:"9.10.2.P1"))
{
  fix = "9.10.2-P2";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:bindVer, fixed_version:fix);
  security_message( data:report, port:bindPort, proto:proto );
  exit( 0 );
}

exit( 99 );