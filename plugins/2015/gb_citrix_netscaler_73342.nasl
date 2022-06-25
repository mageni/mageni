###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_netscaler_73342.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Citrix NetScaler VPX 'large_search.html' Cross-Site Scripting Vulnerability
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

CPE = "cpe:/a:citrix:netscaler";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105272");
  script_bugtraq_id(73342);
  script_cve_id("CVE-2015-2840", "CVE-2015-2838", "CVE-2015-2839");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12106 $");

  script_name("Citrix NetScaler VPX 'large_search.html' Cross-Site Scripting Vulnerability");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected site. This may help the attacker
steal cookie-based authenticationcredentials and launch other attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2015-2840: Cross-site scripting
(XSS) vulnerability in help/rt/large_search.html in Citrix
NetScaler before 10.5 build 52.3nc allows remote attackers
to inject arbitrary web script or HTML via the searchQuery
parameter.

CVE-2015-2839: The Nitro API in Citrix NetScaler before 10.5 build
52.3nc uses an incorrect Content-Type when returning an error message,
which allows remote attackers to conduct cross-site scripting (XSS)
attacks via the file_name JSON member in params/xen_hotfix/0 to
nitro/v1/config/xen_hotfix.

CVE-2015-2838: Cross-site request forgery (CSRF) vulnerability in Nitro
API in Citrix NetScaler before 10.5 build 52.3nc allows remote attackers
to hijack the authentication of administrators for requests that execute
arbitrary commands as nsroot via shell metacharacters in the file_name
JSON member in params/xen_hotfix/0 to nitro/v1/config/xen_hotfix.");

  script_tag(name:"solution", value:"Update to 10.5 build 52.3nc or
newer.");

  script_tag(name:"summary", value:"Citrix NetScaler VPX is prone to multiple cross-site scripting
vulnerabilities and a Cross-site request forgery (CSRF) vulnerability because the application fails
to properly sanitize user-supplied input.");

  script_tag(name:"affected", value:"Citrix NetScaler before 10.5 build
52.3nc");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-12 13:10:00 +0200 (Tue, 12 May 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_citrix_netscaler_version.nasl");
  script_mandatory_keys("citrix_netscaler/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers =  get_app_version( cpe:CPE, nofork: TRUE ) ) exit( 0 );

if( vers !~ '^10\\.5' ) exit( 99 );

if( version_is_less( version: vers, test_version: "10.5.52.3" ) )
{
    report = 'Installed version: ' + vers + '\n' +
             'Fixed version:     10.5 build 52.3\n';

    security_message( port:0, data:report );
    exit (0 );
}

exit( 99 );
