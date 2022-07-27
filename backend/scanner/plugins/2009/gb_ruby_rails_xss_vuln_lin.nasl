###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_rails_xss_vuln_lin.nasl 12673 2018-12-05 15:02:55Z cfischer $
#
# Ruby on Rails 'strip_tags' Cross Site Scripting Vulnerability (Linux)
#
# Authors:
# Antu Sanadi<santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
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
  script_oid("1.3.6.1.4.1.25623.1.0.801078");
  script_version("$Revision: 12673 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 16:02:55 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-12-09 07:52:52 +0100 (Wed, 09 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4214");
  script_bugtraq_id(37142);
  script_name("Ruby on Rails 'strip_tags' Cross Site Scripting Vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_ruby_rails_detect.nasl", "gb_ruby_rails_detect.nasl");
  script_mandatory_keys("RubyOnRails/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37446");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1023245");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3352");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/11/27/2");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site or
  steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Ruby on Rails version before 2.3.5");

  script_tag(name:"insight", value:"This issue is due to the error in 'strip_tagi()' function which is
  not properly escaping non-printable ascii characters.");

  script_tag(name:"solution", value:"Update to Ruby on Rails version 2.3.5 or later.");

  script_tag(name:"summary", value:"The host is running Ruby on Rails, which is prone to Cross Site
  Scripting Vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if(version_is_less( version:vers, test_version:"2.3.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.3.5" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );