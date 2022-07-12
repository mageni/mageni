###############################################################################
# OpenVAS Vulnerability Test
#
# Apple iTunes Multiple Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800543");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2009-03-18 05:31:55 +0100 (Wed, 18 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0143", "CVE-2009-0016");
  script_bugtraq_id(34094);
  script_name("Apple iTunes Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3487");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34254");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");

  script_tag(name:"impact", value:"This issue may be exploited to gain the user's itune credentials when
  subscribing to a malicious podcast and to cause denial of service.");

  script_tag(name:"affected", value:"Apple iTunes version prior to 8.1.0.51 on Windows.");

  script_tag(name:"insight", value:"- the origin of an authentication request is not properly informed to the
  user.

  - an error is generated while processing a Digital Audio Access Protocol
    (DAAP) message containing specially crafted Content-Length parameter in
    the header of a DAAP message.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to iTunes Version 8.1.");

  script_tag(name:"summary", value:"This host has Apple iTunes installed, which is prone to multiple
  vulnerabilities.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less( ersion:vers, test_version:"8.1.0.51" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.1.0.51", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );