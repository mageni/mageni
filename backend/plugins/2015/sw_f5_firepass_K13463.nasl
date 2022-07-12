# Copyright (C) 2015 SCHUTZWERK GmbH
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

CPE = "cpe:/h:f5:firepass";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111017");
  script_version("2021-05-07T11:32:46+0000");
  script_tag(name:"last_modification", value:"2021-05-10 10:15:03 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2015-04-17 08:00:00 +0100 (Fri, 17 Apr 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-1777");

  script_name("F5 FirePass SQL injection vulnerability CVE-2012-1777");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_firepass_detect.nasl");
  script_mandatory_keys("firepass/installed");

  script_tag(name:"summary", value:"F5 FirePass is prone to an SQL injection vulnerability.");

  script_tag(name:"insight", value:"An SQL injection in my.activation.php3 allows remote attackers
  to execute arbitrary SQL commands via the state parameter.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"F5 FirePass version 6.0.0 through 6.1.0 and 7.0.0.");

  script_tag(name:"solution", value:"The vendor has released a Hotfix HF-377712-1 listened in the
  referenced advisory.");

  script_xref(name:"URL", value:"https://support.f5.com/csp/article/K13463");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/111276/F5-FirePass-SSL-VPN-6.x-7.x-SQL-Injection.html");
  script_xref(name:"URL", value:"https://www.sec-consult.com/files/20120328-0_F5_FirePass_SSL_VPN_unauthenticated_remote_root_v1.0.txt");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: HF not detected remotely

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"6.0.0", test_version2:"6.1.0" ) ||
    version_is_equal( version:vers, test_version:"7.0.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.1.0 HF-377712-1/7.0.0 HF-377712-1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );