###############################################################################
# OpenVAS Vulnerability Test
# $Id: tikiwiki_multiple_input_flaws.nasl 13975 2019-03-04 09:32:08Z cfischer $
#
# Tiki Wiki CMS Groupware multiple input validation vulnerabilities
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

# Ref: JeiAr <security@gulftech.org>

CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14364");
  script_version("$Revision: 13975 $");
  script_cve_id("CVE-2004-1923", "CVE-2004-1924", "CVE-2004-1925",
                "CVE-2004-1926", "CVE-2004-1927", "CVE-2004-1928");
  script_bugtraq_id(10100);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Tiki Wiki CMS Groupware multiple input validation vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TikiWiki/installed");

  script_tag(name:"solution", value:"Upgrade to Tiki Wiki CMS Groupware 1.8.2 or newer");

  script_tag(name:"impact", value:"These vulnerabilities may allow a remote attacker to carry out various attacks
  such as path disclosure, cross-site scripting, HTML injection, SQL injection, directory traversal, and arbitrary file upload.");

  script_tag(name:"summary", value:"The remote host is running Tiki Wiki CMS Groupware, a content management system written
  in PHP.

  The remote version of this software is vulnerable to multiple vulnerabilities
  which have been identified in various modules of the application.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.8.2" ) ) {
   report = report_fixed_ver( installed_version:vers, fixed_version:"1.8.2" );
   security_message( port:port, data:report );
   exit( 0 );
}

exit( 99 );
