###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_rails_auth_bypass_vuln.nasl 12673 2018-12-05 15:02:55Z cfischer $
#
# Ruby on Rails Authentication Bypass Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:rubyonrails:ruby_on_rails';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800912");
  script_version("$Revision: 12673 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 16:02:55 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-07-17 12:47:28 +0200 (Fri, 17 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2422");
  script_bugtraq_id(35579);
  script_name("Ruby on Rails Authentication Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_ruby_rails_detect.nasl", "gb_ruby_rails_detect.nasl");
  script_mandatory_keys("RubyOnRails/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35702");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1802");
  script_xref(name:"URL", value:"http://weblog.rubyonrails.org/2009/6/3/security-problem-with-authenticate_with_http_digest");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass authentication by
  providing an invalid username with an empty password and gain unauthorized access to the system.");

  script_tag(name:"affected", value:"Ruby on Rails version 2.3.2 and prior");

  script_tag(name:"insight", value:"This Flaw is caused During login process, the digest authentication functionality
  (http_authentication.rb) returns a 'nil' instead of 'false' when the provided
  username is not found and then proceeds to verify this value against the provided password.");

  script_tag(name:"solution", value:"Update to version 2.3.3 or later.");

  script_tag(name:"summary", value:"The host is running Ruby on Rails, which is prone to Authentication
  Bypass Vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"2.3.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.3.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );