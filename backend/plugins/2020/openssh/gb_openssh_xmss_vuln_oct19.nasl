# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108729");
  script_version("2019-05-23T14:08:05+0000");
  script_cve_id("CVE-2019-16905");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-23 14:08:05 +0000 (Thu, 23 May 2019)");
  script_tag(name:"creation_date", value:"2020-03-23 08:47:12 +0000 (Mon, 23 Mar 2020)");
  script_name("OpenSSH < 8.1 Integer Overflow Vulnerability");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"https://www.openssh.com/txt/release-8.1");
  script_xref(name:"URL", value:"https://0day.life/exploits/0day-1009.html");
  script_xref(name:"URL", value:"https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/sshkey-xmss.c.diff?r1=1.5&r2=1.6&f=h");

  script_tag(name:"summary", value:"OpenSSH is prone to an integer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"An exploitable integer overflow bug was found in the
  private key parsing code for the XMSS key type. This key type is still experimental and
  support for it is not compiled by default. No user-facing autoconf option exists in
  portable OpenSSH to enable it.");

  script_tag(name:"impact", value:"Successfully exploitation could lead to memory corruption
  and local code execution.");

  script_tag(name:"affected", value:"OpenSSH versions 7.7 through 7.9 and 8.x before 8.1.");

  script_tag(name:"solution", value:"Update to version 8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  # nb: Experimental feature not enabled by default so an unreliable QoD is used for
  # Windows-Based systems as well.
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

deb_vers = get_kb_item( "openssh/" + port + "/debian_version" );
if( strlen( deb_vers ) )
  exit( 99 ); # nb: Not enabled in Debian so not affected at all.

if( vers =~ "^7\.[7-9]" || ( vers =~ "^8\." && version_is_less( version:vers, test_version:"8.1" ) ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.1", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
