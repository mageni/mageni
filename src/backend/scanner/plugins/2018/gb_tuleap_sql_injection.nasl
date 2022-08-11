###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tuleap_sql_injection.nasl 9105 2018-03-15 08:34:57Z cfischer $
#
# Tuleap 'CVE-2018-7538' SQL Injection Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:enalean:tuleap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108431");
  script_version("$Revision: 9105 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-15 09:34:57 +0100 (Thu, 15 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-14 16:00:04 +0100 (Wed, 14 Mar 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2018-7738");
  script_name("Tuleap 'CVE-2018-7538' SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_tuleap_detect.nasl");
  script_mandatory_keys("tuleap/installed");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Mar/20");
  script_xref(name:"URL", value:"https://tuleap.net/plugins/tracker/?aid=11192");

  script_tag(name:"summary", value:"Tuleap is prone to a SQL injection vulnerability in the tracker functionality.");

  script_tag(name:"vuldetect", value:"Checks the version.");

  script_tag(name:"insight", value:"Tuleap does not sanitize properly user inputs when constructing SQL queries for
  a tracker report when a criteria is a cross reference or a permissions on artifact field.");

  script_tag(name:"impact", value:"An attacker with access to a tracker report could execute arbitrary SQL queries.");

  script_tag(name:"affected", value:"Tuleap versions before 9.18.");

  script_tag(name:"solution", value:"Update to 9.18 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if (! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"9.18" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.18" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
