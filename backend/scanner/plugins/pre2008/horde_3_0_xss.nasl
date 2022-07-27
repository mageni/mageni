###############################################################################
# OpenVAS Vulnerability Test
# $Id: horde_3_0_xss.nasl 10017 2018-05-30 07:17:29Z cfischer $
#
# Horde 3.0 XSS
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2005 George A. Theall
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

CPE = "cpe:/a:horde:horde_groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16162");
  script_version("$Revision: 10017 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-30 09:17:29 +0200 (Wed, 30 May 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2005-0378");
  script_bugtraq_id(12255);
  script_name("Horde 3.0 XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("horde_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("horde/installed");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/35724/H2005-01.txt.html");

  script_tag(name:"solution", value:"Upgrade to Horde version 3.0.1 or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of Horde version 3.0, which
suffers from two cross site scripting vulnerabilities.

Through specially crafted GET requests to the remote host, an attacker can cause a third party user to unknowingly
run arbitrary Javascript code.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"3.0" ) ||
    version_is_equal( version:vers, test_version:"3.0.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.1");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
