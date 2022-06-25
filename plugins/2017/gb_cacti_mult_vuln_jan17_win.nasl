###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cacti_mult_vuln_jan17_win.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cacti < 1.0.0 Multiple Vulnerabilities (Windows)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:cacti:cacti";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108296");
  script_version("$Revision: 12106 $");
  script_cve_id("CVE-2014-4000", "CVE-2016-2313");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-23 13:54:25 +0100 (Thu, 23 Nov 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("Cacti < 1.0.0 Multiple Vulnerabilities (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cacti_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.cacti.net/release_notes_1_0_0.php");

  script_tag(name:"summary", value:"Cacti is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - a PHP object injection attack and code execution via a crafted serialized object,
  related to calling unserialize(stripslashes()) (CVE-2014-4000).

  - auth_login.php which allows remote authenticated users who use web authentication
  to bypass intended access restrictions by logging in as a user not in the cacti
  database (CVE-2016-2313).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Cacti versions prior to 1.0.0.");

  script_tag(name:"solution", value:"Update to version 1.0.0 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.0.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.0.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
