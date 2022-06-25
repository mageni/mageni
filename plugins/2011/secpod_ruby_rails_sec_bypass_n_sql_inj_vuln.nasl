###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ruby_rails_sec_bypass_n_sql_inj_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Ruby on Rails Security Bypass and SQL Injection Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = 'cpe:/a:rubyonrails:ruby_on_rails';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901187");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_cve_id("CVE-2011-0448", "CVE-2011-0449");
  script_bugtraq_id(46292);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ruby on Rails Security Bypass and SQL Injection Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_ruby_rails_detect.nasl", "gb_ruby_rails_detect.nasl");
  script_mandatory_keys("RubyOnRails/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43278");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025063");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025061");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0343");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
  restrictions and conduct SQL injection attacks.");
  script_tag(name:"affected", value:"Ruby on Rails versions 3.x before 3.0.4");
  script_tag(name:"insight", value:"- The filtering code does not properly work for case insensitive file
    systems, which can be exploited to bypass the filter by varying the case
    in certain action parameters.

  - Input passed to the 'limit()' function is not properly sanitised before
    being used in SQL queries. This can be exploited to manipulate SQL queries
    by injecting arbitrary SQL code.");
  script_tag(name:"solution", value:"Upgrade to Ruby on Rails version 3.0.4 or later.");
  script_tag(name:"summary", value:"This host is running Ruby on Rails and is prone to security bypass
  and SQL injection vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://rubyonrails.org/download");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"3.0.0", test_version2:"3.0.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );