###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_on_rails_action_view_xss_vuln_lin.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# Ruby on Rails Action View Cross Site Scripting Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807380");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-6316");
  script_bugtraq_id(92430);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-13 14:29:55 +0530 (Thu, 13 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Ruby on Rails Action View Cross Site Scripting Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running Ruby on Rails and is
  prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the Text declared as
  'HTML safe' when passed as an attribute value to a tag helper will not have
  quotes escaped which can lead to an XSS attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to inject arbitrary web script or HTML via crafted parameters.");

  script_tag(name:"affected", value:"Ruby on Rails 3.x before 3.2.22.3,
  Ruby on Rails 4.x before 4.2.7.1 and
  Ruby on Rails 5.x before 5.0.0.1 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Ruby on Rails 3.2.22.3 or 4.2.7.1 or
  5.0.0.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q3/260");
  script_xref(name:"URL", value:"https://groups.google.com/forum/#!msg/rubyonrails-security/I-VWr034ouk/gGu2FrCwDAAJ");
  script_xref(name:"URL", value:"http://weblog.rubyonrails.org/2016/8/11/Rails-5-0-0-1-4-2-7-2-and-3-2-22-3-have-been-released");
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

if(RubyonRailVer =~ "^(3\.0)")
{
  if(version_is_less(version:RubyonRailVer, test_version:"3.2.22.3"))
  {
    fix = "3.2.22.3";
    VULN = TRUE;
  }
}

else if(RubyonRailVer =~ "^(4\.0)")
{
  if(version_is_less(version:RubyonRailVer, test_version:"4.2.7.1"))
  {
    fix = "4.2.7.1";
    VULN = TRUE;
  }
}

else if(RubyonRailVer =~ "^(5\.0)")
{
  if(version_is_less(version:RubyonRailVer, test_version:"5.0.0.1"))
  {
    fix = "5.0.0.1";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:RubyonRailVer, fixed_version:fix);
  security_message(port:RubyonRailPort, data:report);
  exit(0);
}
