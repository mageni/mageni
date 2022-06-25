###############################################################################
# OpenVAS Vulnerability Test
#
# Typo3 Persistent Cross Site Scripting Vulnerability Apr18 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = 'cpe:/a:typo3:typo3';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813314");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-6905");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-04-23 15:18:11 +0530 (Mon, 23 Apr 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Typo3 Persistent Cross Site Scripting Vulnerability Apr18 (Windows)");

  script_tag(name:"summary", value:"This host is running Typo3 and is prone
  to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient
  sanitization of user supplied input in the page module.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute a script on victim's Web browser within the security
  context of the hosting Web site.");

  script_tag(name:"affected", value:"Typo3 CMS version 9.1.0 and versions before 8.7.11 on windows.");

  script_tag(name:"solution", value:"Upgrade to 8.7.11 or later for all versions before 8.7.11. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://github.com/pradeepjairamani/TYPO3-XSS-POC");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("TYPO3/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!tyPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:tyPort, version_regex:"[0-9]+\.[0-9]+\.[0-9]+", exit_no_version:TRUE)) exit(0);
tyVer = infos['version'];
path = infos['location'];

if(tyVer == "9.1.0"){
  fix = "Noneavailable";
}
else if(version_is_less(version:tyVer, test_version:"8.7.11")){
  fix = "8.7.11";
}

if(fix)
{
  report = report_fixed_ver(installed_version:tyVer, fixed_version:fix, install_path:path);
  security_message(data:report, port:tyPort);
  exit(0);
}
exit(0);
