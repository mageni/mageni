###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugzilla_41397.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Bugzilla Group Selection During Bug Creation Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:mozilla:bugzilla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100706");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-07-07 12:47:04 +0200 (Wed, 07 Jul 2010)");
  script_bugtraq_id(41397);

  script_name("Bugzilla Group Selection During Bug Creation Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41397");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=574892");
  script_xref(name:"URL", value:"http://www.bugzilla.org");
  script_xref(name:"URL", value:"http://www.bugzilla.org/security/3.7.1/");

  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("bugzilla_detect.nasl");
  script_mandatory_keys("bugzilla/installed");
  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain potentially sensitive
information that may aid in other attacks.");
  script_tag(name:"affected", value:"Bugzilla 3.7 and 3.7.1 are vulnerable.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"Bugzilla is prone to an information-disclosure vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( port:port, cpe:CPE ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"3.7" ) ||
    version_is_equal( version:vers, test_version:"3.7.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.7.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
