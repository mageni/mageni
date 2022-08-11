###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cups_dos_vuln_jun09.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# CUPS Denial of Service Vulnerability - Jun09
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800584");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1196", "CVE-2009-0791");
  script_bugtraq_id(35194, 35195);
  script_name("CUPS Denial of Service Vulnerability - Jun09");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_cups_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("CUPS/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35340");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1083.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Jun/1022327.html");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute
  arbitrary code and can cause denial of service.");

  script_tag(name:"affected", value:"CUPS versions prior to 1.4.0 on Linux");

  script_tag(name:"insight", value:"The flaws are due to

  - A use-after-free error within the directory-services functionality in the
  scheduler.

  - Integer overflow errors within the 'pdftops' filter while processing
  specially crafted PDF file.");

  script_tag(name:"solution", value:"Upgrade CUPS to version 1.4.0 or higher.");

  script_tag(name:"summary", value:"This host is running CUPS (Common UNIX Printing System)
  Service, which is prone to Denial of Service vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( vers !~ "[0-9]+\.[0-9]+\.[0-9]+") exit( 0 ); # Version is not exact enough

if( version_is_less( version:vers, test_version:"1.4.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );