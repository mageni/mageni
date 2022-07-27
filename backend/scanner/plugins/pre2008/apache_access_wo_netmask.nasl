###############################################################################
# OpenVAS Vulnerability Test
# $Id: apache_access_wo_netmask.nasl 12007 2018-10-22 07:43:49Z cfischer $
#
# Description: Apache mod_access rule bypass
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004 George A. Theall
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14177");
  script_version("$Revision: 12007 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 09:43:49 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9829);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0993");
  script_name("Apache mod_access rule bypass");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl");
  script_mandatory_keys("apache/installed");


  script_xref(name:"URL", value:"http://www.apacheweek.com/features/security-13");
  script_xref(name:"URL", value:"https://marc.info/?l=apache-cvs&m=107869603013722");
  script_xref(name:"URL", value:"http://nagoya.apache.org/bugzilla/show_bug.cgi?id=23850");

  script_tag(name:"solution", value:"Upgrade to Apache version 1.3.31 or newer.");

  script_tag(name:"summary", value:"The target is running an Apache web server that may not properly handle
  access controls.");

  script_tag(name:"insight", value:"In effect, on big-endian 64-bit platforms, Apache
  fails to match allow or deny rules containing an IP address but not a netmask.
  Additional information on the vulnerability can be found at the referenced links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! info = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
vers = info['version'];
path = info['location'];

if( version_is_less( version:vers, test_version:"1.3.31" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.31", install_path:path );
  security_message( port:port, data:report );
}

exit( 0 );