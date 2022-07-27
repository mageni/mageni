###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_on_rails_mult_vuln01_oct16_lin.nasl 11903 2018-10-15 10:26:16Z asteins $
#
# Ruby on Rails Multiple Vulnerabilities-01 Oct16 (Linux)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809357");
  script_version("$Revision: 11903 $");
  script_cve_id("CVE-2016-0752", "CVE-2016-0751", "CVE-2015-7576");
  script_bugtraq_id(81801, 81800, 81803);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 12:26:16 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-17 18:48:40 +0530 (Mon, 17 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Ruby on Rails Multiple Vulnerabilities-01 Oct16 (Linux)");

  script_tag(name:"summary", value:"This host is running Ruby on Rails and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The directory traversal vulnerability in Action View.

  - The script 'actionpack/lib/action_dispatch/http/mime_type.rb' does not properly
    restrict use of the MIME type cache.

  - The http_basic_authenticate_with method in
    'actionpack/lib/action_controller/metal/http_authentication.rb' does not use a
    constant-time algorithm for verifying credentials.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read arbitrary files by leveraging an application's unrestricted use
  of the render method, to cause a denial of service.");

  script_tag(name:"affected", value:"Ruby on Rails before 3.2.22.1,
  Ruby on Rails 4.0.x and 4.1.x before 4.1.14.1 and
  Ruby on Rails 4.2.x before 4.2.5.1 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Ruby on Rails 3.2.22.1 or
  4.1.14.1 or 4.2.5.1, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/01/25/10");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_ruby_rails_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("RubyOnRails/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 3000);
  script_xref(name:"URL", value:"http://rubyonrails.org");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!RubyonRailPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!RubyonRailVer = get_app_version(cpe:CPE, port:RubyonRailPort)){
  exit(0);
}

if(version_is_less(version:RubyonRailVer, test_version:"3.2.22.1"))
{
  fix = "3.2.22.1";
  VULN = TRUE;
}

else if(RubyonRailVer =~ "^(4\.)")
{
  if(version_is_less(version:RubyonRailVer, test_version:"4.1.14.1"))
  {
    fix = "4.1.14.1";
    VULN = TRUE;
  }
}

else if(RubyonRailVer =~ "^(4\.2)")
{
  if(version_is_less(version:RubyonRailVer, test_version:"4.2.5.1"))
  {
    fix = "4.2.5.1";
    VULN = TRUE;
  }
}

##Beta versions not considered

if(VULN)
{
  report = report_fixed_ver(installed_version:RubyonRailVer, fixed_version:fix);
  security_message(port:RubyonRailPort, data:report);
  exit(0);
}
