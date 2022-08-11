###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cups_mult_vuln_oct08.nasl 14010 2019-03-06 08:24:33Z cfischer $
#
# CUPS Multiple Vulnerabilities - Oct08
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800111");
  script_version("$Revision: 14010 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-14 16:26:50 +0200 (Tue, 14 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-3639", "CVE-2008-3640", "CVE-2008-3641");
  script_bugtraq_id(31681, 31688, 31690);
  script_name("CUPS Multiple Vulnerabilities - Oct08");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_cups_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("CUPS/installed");

  script_xref(name:"URL", value:"http://cups.org/articles.php?L575");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32226/");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2782/");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code or
  compromise a vulnerable system.");

  script_tag(name:"affected", value:"CUPS versions prior to 1.3.9.");

  script_tag(name:"insight", value:"The flaws are due to

  - an error in the implementation of the HP-GL/2 filter and can be
  exploited to cause buffer overflows with HP-GL/2 files containing overly
  large pen numbers.

  - an error within the read_rle8() and read_rle16() functions when
  parsing malformed Run Length Encoded(RLE) data within Silicon Graphics
  Image(SGI) files and can exploited to cause heap-based buffer overflow
  with a specially crafted SGI file.

  - an error within the WriteProlog() function included in the texttops
  utility and can be exploited to cause a heap-based buffer overflow with
  specially crafted file.");

  script_tag(name:"solution", value:"Upgrade to CUPS version 1.3.9 or later.");

  script_tag(name:"summary", value:"This host is running CUPS (Common UNIX Printing System) Service,
  which is prone to Buffer Overflow and Integer Overflow Vulnerabilities.");

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

if( vers !~ "[0-9]+\.[0-9]+\.[0-9]+")
  exit( 0 ); # Version is not exact enough

if( version_is_less( version:vers, test_version:"1.3.9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.9" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );