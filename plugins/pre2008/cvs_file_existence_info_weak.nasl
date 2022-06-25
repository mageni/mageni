###############################################################################
# OpenVAS Vulnerability Test
# $Id: cvs_file_existence_info_weak.nasl 12011 2018-10-22 08:58:15Z cfischer $
#
# CVS file existence information disclosure weakness
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

CPE = "cpe:/a:cvs:cvs";

# Ref: Sebastian Krahmer

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14313");
  script_version("$Revision: 12011 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 10:58:15 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10955);
  script_cve_id("CVE-2004-0778");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("CVS file existence information disclosure weakness");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("General");
  script_dependencies("cvspserver_version.nasl");
  script_mandatory_keys("cvspserver/detected");

  script_tag(name:"solution", value:"Upgrade to CVS 1.11.17 and 1.12.9, or newer.");

  script_tag(name:"summary", value:"The remote CVS server, according to its version number,
  can be exploited by malicious users to gain knowledge of certain system information.");

  script_tag(name:"impact", value:"This behaviour can be exploited to determine the existence
  and permissions of arbitrary files and directories on a vulnerable system.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.11.17" ) ||
    version_in_range( version:vers, test_version:"1.12", test_version2:"1.12.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.11.17/1.12.9" );
  security_message( port:port, data:report );
}

exit( 0 );