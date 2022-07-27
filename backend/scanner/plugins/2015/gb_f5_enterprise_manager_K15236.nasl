# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:f5:enterprise_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105306");
  script_bugtraq_id(69461);
  script_cve_id("CVE-2014-2927");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("2021-05-07T11:32:46+0000");
  script_name("F5 Enterprise Manager - ConfigSync IP Rsync full file system access vulnerability CVE-2014-2927");
  script_tag(name:"last_modification", value:"2021-05-10 10:15:03 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2015-06-24 14:31:00 +0200 (Wed, 24 Jun 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("Gain a shell remotely");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_f5_enterprise_manager_version.nasl");
  script_mandatory_keys("f5/f5_enterprise_manager/version", "f5/f5_enterprise_manager/hotfix");

  script_xref(name:"URL", value:"https://support.f5.com/csp/article/K15236");

  script_tag(name:"summary", value:"F5 Networks Enterprise Manager is prone to a remote
  code-execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An open Rsync configuration for the ConfigSync IP address allows
  for remote read/write file system access in Enterprise Manager.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code
  within the context of the application.");

  script_tag(name:"affected", value:"Enterprise Manager 3.x version before 3.1.1 HF2.");

  script_tag(name:"solution", value:"Update to Enterprise Manager 3.1.1 HF2 or higher.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE ) )
  exit( 0 );

if( version_is_equal( version:vers, test_version:"3.1.1" ) ) {
  hotfix = get_kb_item( "f5/f5_enterprise_manager/hotfix" );
  if( int( hotfix ) >= 2 )
    exit( 0 );
}

if( version_in_range( version:vers, test_version:"3", test_version2:"3.1.1") ) {
  report = report_fixed_ver( installed_version:vers + " HF" + hotfix, fixed_version:"3.1.1 HF2" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );