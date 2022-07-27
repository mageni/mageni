# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113380");
  script_version("2019-06-13T11:02:17+0000");
  script_tag(name:"last_modification", value:"2019-06-13 11:02:17 +0000 (Thu, 13 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-04-29 12:27:28 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2019-11513", "CVE-2019-11226");

  script_name("CMS Made Simple <= 2.2.10 Reflected Mutliple Cross-Site Scripting (XSS) Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cms_made_simple_detect.nasl");
  script_mandatory_keys("cmsmadesimple/installed");

  script_tag(name:"summary", value:"CMS Made Simple is prone to multiple cross-site scripting (XSS) vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - The File Manager is prone to reflected XSS via the 'New Name' field in a Rename action.

  - XSS Vulnerability via the m1_name parameter in 'Add Article' under Content->Content Manager->News.");
  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to inject arbitrary
  JavaScript and HTML into the site.");
  script_tag(name:"affected", value:"CMS Made Simple through version 2.2.10.");
  script_tag(name:"solution", value:"No known solution is available as of 13th June, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"http://dev.cmsmadesimple.org/bug/view/12022");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/153071/CMS-Made-Simple-2.2.10-Cross-Site-Scripting.html");

  exit(0);
}

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "2.2.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None Available" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
