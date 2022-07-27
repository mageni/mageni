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
  script_oid("1.3.6.1.4.1.25623.1.0.113373");
  script_version("2019-04-30T06:00:47+0000");
  script_tag(name:"last_modification", value:"2019-04-30 06:00:47 +0000 (Tue, 30 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-24 13:32:43 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-11454", "CVE-2019-11455");

  script_name("Tildeslash Monit < 5.25.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_monit_detect.nasl");
  script_mandatory_keys("monit/detected");

  script_tag(name:"summary", value:"Monit is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - Persistent Cross-Site Scripting (XSS) in http/cervlet.c allows a remote
    unauthenticated attacker to introduce arbitrary JavaScript via manipulation
    of an unsanitized user field of the Authorization header for HTTP Basic Authentication,
    which is mishandled during a _viewlog operation

  - A buffer over-read in Util_urlDecode allows a remote authenticated attacker
    to retrieve the contents of adjacent memory via manipulation of GET or POST parameters.
    The attacker can also use this to cause a Denial of Service");
  script_tag(name:"affected", value:"Monit through version 5.25.2.");
  script_tag(name:"solution", value:"Update to version 5.25.3.");

  script_xref(name:"URL", value:"https://github.com/dzflack/exploits/blob/master/unix/monit_buffer_overread.py");
  script_xref(name:"URL", value:"https://github.com/dzflack/exploits/blob/master/macos/monit_dos.py");
  script_xref(name:"URL", value:"https://github.com/dzflack/exploits/blob/master/unix/monit_xss.py");

  exit(0);
}

CPE = "cpe:/a:tildeslash:monit";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "5.25.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.25.3" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
