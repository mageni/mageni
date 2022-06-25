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
  script_oid("1.3.6.1.4.1.25623.1.0.113334");
  script_version("2019-04-03T09:59:09+0000");
  script_tag(name:"last_modification", value:"2019-04-03 09:59:09 +0000 (Wed, 03 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-13 10:50:14 +0200 (Wed, 13 Feb 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2019-7544", "CVE-2019-7730", "CVE-2019-7731");

  script_name("MyWebSQL <= 3.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mywebsql_http_detect.nasl");
  script_mandatory_keys("mywebsql/detected");

  script_tag(name:"summary", value:"MyWebSQL is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - The Add User function of the User Manager pages has a
    Stored Cross-Site Scripting (XSS) vulnerability in the User Name Field

  - Cross-Site Request Forgery (CSRF) for deleting a database
    via the /?q=wrkfrm&type=databases URI

  - Remote Code Execution (RCE) vulnerability after an attacker writes shell
    code into the database, and executes the Backup Database function with
    a .php filename for the backup's archive file");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute arbitrary code
  on the target machine.");
  script_tag(name:"affected", value:"MyWebSQL through version 3.7.");
  script_tag(name:"solution", value:"No known solution is available as of 03rd April, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/eddietcc/CVEnotes/blob/master/MyWebSQL/CSRF/readme.md");
  script_xref(name:"URL", value:"https://github.com/eddietcc/CVEnotes/blob/master/MyWebSQL/RCE/readme.md");
  script_xref(name:"URL", value:"https://github.com/0xUhaw/CVE-Bins/blob/master/MyWebSQL/Readme.md");

  exit(0);
}

CPE = "cpe:/a:mywebsql:mywebsql";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "3.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None Available" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
