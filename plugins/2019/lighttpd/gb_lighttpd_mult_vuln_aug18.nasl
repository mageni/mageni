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

CPE = "cpe:/a:lighttpd:lighttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108549");
  script_version("$Revision: 13753 $");
  script_cve_id("CVE-2018-19052");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 10:45:52 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-19 10:42:10 +0100 (Tue, 19 Feb 2019)");
  script_name("Lighttpd < 1.4.50 Multiple Vulnerabilities");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("sw_lighttpd_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("lighttpd/installed");

  script_xref(name:"URL", value:"https://www.lighttpd.net/2018/8/13/1.4.50/");
  script_xref(name:"URL", value:"https://redmine.lighttpd.net/issues/2898");
  script_xref(name:"URL", value:"https://github.com/lighttpd/lighttpd1.4/commit/2105dae0f9d7a964375ce681e53cb165375f84c1");

  script_tag(name:"summary", value:"This host is running Lighttpd which is prone to
  multiple path traversal and use-after-free vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation might allow a remote
  attacker to execute arbitrary code on affected system or conduct path traversal
  attacks to get unauthorized access to files on the hosts filesystem.");

  script_tag(name:"affected", value:"Lighttpd versions before 1.4.50.");

  script_tag(name:"solution", value:"Upgrade to version 1.4.50 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"1.4.50" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.50" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );