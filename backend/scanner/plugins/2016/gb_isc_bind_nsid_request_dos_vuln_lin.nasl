##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_isc_bind_nsid_request_dos_vuln_lin.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# ISC BIND NSID Request Denial of Service Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.809461");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-2848");
  script_bugtraq_id(93814);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-24 18:23:32 +0530 (Mon, 24 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND NSID Request Denial of Service Vulnerability (Linux)");

  script_tag(name:"summary", value:"The host is installed with ISC BIND and is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to mishandling of
  packets with malformed options. A remote attacker could use this flaw to make
  named exit unexpectedly with an assertion failure via a specially crafted DNS
  packet.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service.");

  script_tag(name:"affected", value:"ISC BIND versions 9.1.0 through 9.8.4-P2
  and 9.9.0 through 9.9.2-P2 on Linux.");

  script_tag(name:"solution", value:"Upgrade to ISC BIND version 9.9.9-P3 or
  9.10.4-P3 or 9.11.0 or later on Linux.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01433/74/CVE-2016-2848");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("bind_version.nasl", "os_detection.nasl");
  script_mandatory_keys("ISC BIND/installed", "Host/runs_unixoide");
  script_xref(name:"URL", value:"https://www.isc.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! bindPort = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:bindPort ) ) exit( 0 );

bindVer = infos["version"];
proto = infos["proto"];

if(version_in_range(version:bindVer, test_version:"9.1.0", test_version2:"9.8.4.P2") ||
   version_in_range(version:bindVer, test_version:"9.9.0", test_version2:"9.9.2.P2"))
{
  report = report_fixed_ver(installed_version:bindVer, fixed_version:"9.9.9-P3 or 9.10.4-P3 or 9.11.0");
  security_message( data:report, port:bindPort, proto:proto );
  exit( 0 );
}

exit( 99 );