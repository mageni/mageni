# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.108826");
  script_version("2020-07-30T12:19:10+0000");
  script_tag(name:"last_modification", value:"2020-07-31 10:00:11 +0000 (Fri, 31 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-30 07:52:41 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-4883");

  script_name("lwIP TCP/IP Stack DNS Resolver <= 1.4.1 Cache-Poisoning Attack Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_lwip_http_detect.nasl");
  script_mandatory_keys("lwip/detected");

  script_tag(name:"summary", value:"The lwIP TCP/IP Stack DNS Resolver is vulnerable against a cache-poisoning attack.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"'dns.c' in the DNS resolver in lwIP does not use random values for ID fields and source
  ports of DNS query packets, which makes it easier for man-in-the-middle attackers to conduct cache-poisoning attacks via
  spoofed reply packets.");

  script_tag(name:"affected", value:"lwIP TCP/IP Stack DNS Resolver 1.4.1 and earlier.");

  script_tag(name:"solution", value:"Update to version 2.0.0 or later.");

  script_xref(name:"URL", value:"http://git.savannah.gnu.org/cgit/lwip.git/commit/?id=9fb46e120655ac481b2af8f865d5ae56c39b831a");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/210620");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:lwip_project:lwip";

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( port:port, cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"2.0.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.0", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
