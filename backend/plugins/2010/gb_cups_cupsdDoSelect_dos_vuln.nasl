###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cups_cupsdDoSelect_dos_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# CUPS 'scheduler/select.c' Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800487");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-0302");
  script_bugtraq_id(38510);
  script_name("CUPS 'scheduler/select.c' Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_cups_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("CUPS/installed");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/USN-906-1");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2010-0129.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=557775");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute
  arbitrary code and can cause denial of service.");
  script_tag(name:"affected", value:"CUPS versions 1.3.x, 1.4.x on Linux.");
  script_tag(name:"insight", value:"The flaw is due to an use-after-free error within the
  'cupsdDoSelect()' function in 'scheduler/select.c' when kqueue or epoll is
  used, allows remote attackers to crash or hang the daemon via a client
  disconnection during listing of a large number of print jobs.");
  script_tag(name:"solution", value:"Upgrade to version 1.5 or later, *****
  NOTE: Please ignore this warning if the patch is applied.
  *****");
  script_tag(name:"summary", value:"This host is running CUPS (Common UNIX Printing System) Service,
  which is prone to Denial of Service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.cups.org/software.php");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers !~ "[0-9]+\.[0-9]+\.[0-9]+") exit( 0 ); # Version is not exact enough

if( version_in_range( version:vers, test_version:"1.4.0", test_version2:"1.4.1" ) ||
    version_in_range( version:vers, test_version:"1.3.0", test_version2:"1.3.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.5" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );