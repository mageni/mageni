###############################################################################
# OpenVAS Vulnerability Test
#
# Node.js 'debugger' Privilege Escalation Vulnerability-(Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.814519");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-12120");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-29 13:25:38 +0530 (Thu, 29 Nov 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Node.js 'debugger' Privilege Escalation Vulnerability-(Windows)");

  script_tag(name:"summary", value:"The host is installed with Node.js and is
  prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in due to an error in 'Debugger'.
  Debugger port 5858 listens on any interface by default, When the debugger
  is enabled with 'node --debug' or 'node debug'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct spoofing attacks.");

  script_tag(name:"affected", value:"Node.js versions prior to 6.15.0 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Node.js version 6.15.0 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/november-2018-security-releases");
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

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
nodejsVer = infos['version'];
appPath = infos['location'];

if(version_is_less(version:nodejsVer, test_version:"6.15.0"))
{
  report = report_fixed_ver(installed_version:nodejsVer, fixed_version:"6.15.0", install_path:appPath);
  security_message(data:report);
  exit(0);
}

exit(99);