###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_phantompdf_mult_vuln.nasl 12026 2018-10-23 08:22:54Z mmartin $
#
# Foxit PhantomPDF 7.3.4.311 Multiple Vulnerabilities
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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


if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113108");
  script_version("$Revision: 12026 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 10:22:54 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-08 14:00:00 +0100 (Thu, 08 Feb 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2016-6168", "CVE-2016-6169");

  script_name("Foxit Reader 7.3.4.311 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("foxit/phantompdf/ver");

  script_tag(name:"summary", value:"Foxit PhantomPDF is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Use-after-free / Buffer overflow vulnerability in Foxit Reader can be exploited via a crafted PDF file.");
  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to cause a Denial of Service or execute arbitrary code on the target host.");
  script_tag(name:"affected", value:"Foxit PhantomPDF through version 7.3.4.311");
  script_tag(name:"solution", value:"Update to Foxit PhantomPDF 8.0 or above.");

  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-16-021");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  exit(0);
}

CPE = "cpe:/a:foxitsoftware:phantompdf";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if( version_is_less_equal( version: vers, test_version: "7.3.4.311" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "8.0", install_path: path );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
