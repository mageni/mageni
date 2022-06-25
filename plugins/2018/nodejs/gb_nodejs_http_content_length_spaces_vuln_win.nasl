###############################################################################
# OpenVAS Vulnerability Test
#
# Node.js Spaces in 'HTTP Content-Length Header' Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813472");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-7159");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-09 17:20:49 +0530 (Mon, 09 Jul 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Node.js Spaces in 'HTTP Content-Length Header' Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with Node.js and is
  prone to ignoring spaces in HTTP content length header vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the HTTP
  parser which ignores spaces in the Content-Length header, allowing input such
  as Content-Length: 1 2 to be interpreted as having a value of 12.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to send spaces in the Content-Length header and bypass 'Content-Length'
  restriction policy.");

  script_tag(name:"affected", value:"Node.js versions 4.x prior to 4.9.0, 6.x
  prior to 6.14.0, 8.x prior to 8.11.0 and 9.x prior to 9.10.0");

  script_tag(name:"solution", value:"Upgrade to Node.js version 4.9.0 or 6.14.0
  or 8.11.0 or 9.10.0 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/march-2018-security-releases/");
  script_xref(name:"URL", value:"https://nodejs.org");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_nodejs_detect_win.nasl");
  script_mandatory_keys("Nodejs/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( appPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:appPort, exit_no_version:TRUE ) ) exit( 0 );
nodejsVer = infos['version'];
appPath = infos['location'];

if(nodejsVer =~ "^4\." && version_is_less(version:nodejsVer, test_version:"4.9.0")){
  fix = "4.9.0";
}

else if(nodejsVer =~ "^6\." && version_is_less(version:nodejsVer, test_version:"6.14.0")){
  fix = "6.14.0";
}

else if(nodejsVer =~ "^8\." && version_is_less(version:nodejsVer, test_version:"8.11.0")){
  fix = "8.11.0";
}

else if(nodejsVer =~ "^9\." && version_is_less(version:nodejsVer, test_version:"9.10.0")){
  fix = "9.10.0";
}

if(fix)
{
  report = report_fixed_ver(installed_version:nodejsVer, fixed_version:fix, install_path:appPath);
  security_message(port:appPort, data:report);
  exit(0);
}
exit(0);
