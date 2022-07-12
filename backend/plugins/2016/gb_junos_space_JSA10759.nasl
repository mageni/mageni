###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_space_JSA10759.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# Junos Space OpenSSL Security Updates
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
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:juniper:junos_space";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140019");
  script_version("$Revision: 14181 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-10-26 14:51:46 +0200 (Wed, 26 Oct 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-0703", "CVE-2016-0800", "CVE-2016-2108", "CVE-2016-6304", "CVE-2015-3194",
                "CVE-2015-3195", "CVE-2016-0704", "CVE-2015-3197", "CVE-2016-0702", "CVE-2016-0797",
                "CVE-2016-0799", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2109", "CVE-2016-6303",
                "CVE-2016-2179", "CVE-2016-2182", "CVE-2016-2180", "CVE-2016-2181", "CVE-2016-6302",
                "CVE-2016-2177", "CVE-2016-2178", "CVE-2016-6306");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Junos Space OpenSSL Security Updates");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_junos_space_version.nasl");
  script_mandatory_keys("junos_space/installed");

  script_tag(name:"summary", value:"The OpenSSL project has published a set of security advisories for vulnerabilities resolved in the OpenSSL library in December 2015, March, May, June, August and September 2016. Junos Space is potentially affected by many of these issues.");

  script_tag(name:"affected", value:"Junos Space < 16.1R1");

  script_tag(name:"solution", value:"OpenSSL software has been upgraded to 1.0.1t in Junos Space 16.1R1 (pending release) to resolve all the issues.");

  script_xref(name:"URL", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10759");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("junos.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe: CPE ) )
  exit( 0 );

if( check_js_version( ver:version, fix:"16.1R1" ) )
{
  report = report_fixed_ver( installed_version:version, fixed_version:"16.1R1" );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );