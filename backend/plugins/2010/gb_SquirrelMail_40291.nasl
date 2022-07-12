###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_SquirrelMail_40291.nasl 14033 2019-03-07 11:09:35Z cfischer $
#
# SquirrelMail 'mail_fetch' Remote Information Disclosure Vulnerability
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

CPE = 'cpe:/a:squirrelmail:squirrelmail';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100688");
  script_version("$Revision: 14033 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 12:09:35 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-06-22 12:10:21 +0200 (Tue, 22 Jun 2010)");
  script_bugtraq_id(40291);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_cve_id("CVE-2010-1637");
  script_name("SquirrelMail 'mail_fetch' Remote Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("squirrelmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("squirrelmail/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/40291");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/2935");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/3064");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/2936");
  script_xref(name:"URL", value:"http://conference.hitb.org/hitbsecconf2010dxb/materials/D1%20-%20Laurent%20Oudot%20-%20Improving%20the%20Stealthiness%20of%20Web%20Hacking.pdf#page=69");
  script_xref(name:"URL", value:"http://www.squirrelmail.org");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain potentially sensitive
  information that may lead to further attacks.");

  script_tag(name:"affected", value:"This issue affects SquirrelMail 1.4.x versions.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"SquirrelMail is prone to a remote information-disclosure
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"1.4", test_version2:"1.4.20" ) ||
    version_in_range( version:vers, test_version:"1.5", test_version2:"1.5.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.21/1.5.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );