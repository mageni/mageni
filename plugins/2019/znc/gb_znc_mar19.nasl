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

CPE = "cpe:/a:znc:znc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108604");
  script_version("2019-06-18T06:52:36+0000");
  script_tag(name:"last_modification", value:"2019-06-18 06:52:36 +0000 (Tue, 18 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-17 06:47:14 +0000 (Mon, 17 Jun 2019)");
  script_cve_id("CVE-2019-9917");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("ZNC < 1.7.3-rc1 Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("znc_detect.nasl");
  script_mandatory_keys("znc/installed");

  script_xref(name:"URL", value:"https://wiki.znc.in/ChangeLog/1.7.3");
  script_xref(name:"URL", value:"https://github.com/znc/znc/commit/64613bc8b6b4adf1e32231f9844d99cd512b8973");

  script_tag(name:"summary", value:"The host is running an ZNC IRC bouncer which is prone to a
  Denial of Service vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation allows an existing remote user to cause a Denial of Service (crash).");

  script_tag(name:"affected", value:"ZNC before 1.7.3-rc1.");

  script_tag(name:"solution", value:"Upgrade to ZNC 1.7.3-rc1 or later. Please see the references for more information.");

  script_tag(name:"insight", value:"The flaw can be triggered by an attacker by using an invalid encoding.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version2:"1.7.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.7.3-rc1", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );