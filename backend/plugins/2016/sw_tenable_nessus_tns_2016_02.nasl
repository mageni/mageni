###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_tenable_nessus_tns_2016_02.nasl 12083 2018-10-25 09:48:10Z cfischer $
#
# Tenable Nessus Multiple Vulnerabilities Feb16
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (C) 2016 SCHUTZWERK GmbH, http://www.schutzwerk.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:tenable:nessus';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111087");
  script_version("$Revision: 12083 $");
  script_cve_id("CVE-2016-82000", "CVE-2016-82001");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 11:48:10 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-16 09:00:00 +0100 (Tue, 16 Feb 2016)");
  script_name("Tenable Nessus Multiple Vulnerabilities Feb16");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");
  script_require_ports("Services/www", 8834);

  script_tag(name:"summary", value:"This host is installed with Nessus and is prone to:

  - stored Cross-Site Scripting vulnerabilities

  - a possible privilege escalation vulnerability on scanned hosts running Mac OS X");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain knowledge on
  sensitive information.");

  script_tag(name:"affected", value:"Tenable Nessus versions 5.x and 6.0 - 6.5.4");

  script_tag(name:"solution", value:"Upgrade Tenable Nessus to 6.5.5.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2016-02");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"5.0", test_version2:"6.5.4" ) ) {
   report = report_fixed_ver( installed_version:vers, fixed_version:"6.5.5" );
   security_message( port:port, data:report );
   exit( 0 );
}

exit( 99 );
