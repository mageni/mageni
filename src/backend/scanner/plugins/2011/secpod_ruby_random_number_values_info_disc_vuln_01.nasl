###############################################################################
# OpenVAS Vulnerability Test
#
# Ruby Random Number Values Information Disclosure Vulnerability
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

CPE = "cpe:/a:ruby-lang:ruby";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902560");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-2011-2705");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Ruby Random Number Values Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=722415");
  script_xref(name:"URL", value:"http://www.ruby-lang.org/en/news/2011/07/02/ruby-1-8-7-p352-released/");
  script_xref(name:"URL", value:"http://www.ruby-lang.org/en/news/2011/07/15/ruby-1-9-2-p290-is-released/");

  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_ruby_detect_win.nasl");
  script_mandatory_keys("Ruby/Win/Installed");
  script_tag(name:"impact", value:"Successful exploits may allow attackers to predict random number values.");
  script_tag(name:"affected", value:"Ruby versions before 1.8.7-p352 and 1.9.x before 1.9.2-p290");
  script_tag(name:"insight", value:"The flaw exists because the SecureRandom.random_bytes function in
  lib/securerandom.rb relies on PID values for initialization, which makes it
  easier for context-dependent attackers to predict the result string by
  leveraging knowledge of random strings obtained in an earlier process with
  the same PID.");
  script_tag(name:"solution", value:"Upgrade to Ruby version 1.8.7-p352, 1.9.2-p290 or later");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Ruby and is prone to information
  disclosure vulnerability.");
  script_xref(name:"URL", value:"http://rubyforge.org/frs/?group_id=167");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_in_range( version:vers, test_version:"1.8.7", test_version2:"1.8.7.p351" ) ||
    version_in_range( version:vers, test_version:"1.9", test_version2:"1.9.2.p289" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.8.7-p352 / 1.9.2-p290", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
