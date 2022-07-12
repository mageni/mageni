###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trend_micro_interscan_web_security_virtual_appliance_70964.nasl 12083 2018-10-25 09:48:10Z cfischer $
#
# Trend Micro InterScan Web Security Virtual Appliance Multiple Information Disclosure Vulnerabilities
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

CPE = "cpe:/a:trendmicro:interscan_web_security_virtual_appliance";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105247");
  script_bugtraq_id(70964);
  script_cve_id("CVE-2014-8510");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_version("$Revision: 12083 $");

  script_name("Trend Micro InterScan Web Security Virtual Appliance Multiple Information Disclosure Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70964");
  script_xref(name:"URL", value:"http://www.trend.com");

  script_tag(name:"impact", value:"Attackers can exploit these issues to obtain potentially sensitive
  information that may lead to further attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version/build is present on the target host.");

  script_tag(name:"insight", value:"The AdminUI in Trend Micro InterScan Web Security Virtual Appliance (IWSVA)
  allows remote authenticated users to read arbitrary files via vectors related to configuration input when saving filters.");

  script_tag(name:"solution", value:"Update to 6.0 HF build 1244 or later.");

  script_tag(name:"summary", value:"Trend Micro InterScan Web Security Virtual Appliance is prone to
  multiple information-disclosure vulnerabilities.");

  script_tag(name:"affected", value:"Trend Micro InterScan Web Security Virtual Appliance (IWSVA) before 6.0 HF build 1244.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 11:48:10 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-04-08 10:22:02 +0200 (Wed, 08 Apr 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_trend_micro_interscan_web_security_virtual_appliance_version.nasl");
  script_mandatory_keys("IWSVA/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers =  get_app_version( cpe:CPE ) )
  if( ! vers = get_kb_item( "IWSVA/version" ) ) exit( 0 );

if( ! build = get_kb_item( "IWSVA/build" ) ) build = 0;

if( version_is_less( version:vers, test_version:"6.0" ) )
{
  vuln = TRUE;
}

if( vers == "6.0" && int(build) < 1244 )
{
  vuln = TRUE;
}

if( vuln )
{
  report = 'Installed Version: ' + vers + '\n' +
           'Installed Build:   ' + build + '\n\n' +
           'Fixed Version:     6.0\n' +
           'Fixed Build:       1244';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );