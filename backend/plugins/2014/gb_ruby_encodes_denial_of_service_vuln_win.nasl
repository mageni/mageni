###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_encodes_denial_of_service_vuln_win.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# Ruby 'encodes' function Denial-of-Service Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804887");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2014-4975");
  script_bugtraq_id(68474);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-11-20 17:12:57 +0530 (Thu, 20 Nov 2014)");
  script_name("Ruby 'encodes' function Denial-of-Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Ruby and is
  prone to denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to improper bounds checking
  by the 'encodes' function in pack.c script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a denial of service (crash) or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"Ruby versions 1.9.3 and earlier and 2.x
  through 2.1.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Ruby 2.1.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59731");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/94706");
  script_xref(name:"URL", value:"https://bugs.ruby-lang.org/issues/10019");
  script_xref(name:"URL", value:"http://svn.ruby-lang.org/repos/ruby/tags/v2_1_3/ChangeLog");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_ruby_detect_win.nasl");
  script_mandatory_keys("Ruby/Win/Installed");
  script_xref(name:"URL", value:"http://www.ruby-lang.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!rubyVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(rubyVer)
{
  if(version_is_less_equal(version:rubyVer, test_version:"1.9.3")||
     version_in_range(version:rubyVer, test_version:"2.0.0",test_version2:"2.1.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
