###############################################################################
# OpenVAS Vulnerability Test
#
# Joomla! Core Multiple Vulnerabilities-01 May18 (20180502/20180501)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813408");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-11323", "CVE-2018-11322");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-23 12:35:14 +0530 (Wed, 23 May 2018)");

  script_name("Joomla! Core Multiple Vulnerabilities-01 May18 (20180502/20180501)");

  script_tag(name:"summary", value:"This host is running Joomla and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to:

  - An error where depending on the server configuration, PHAR files might be handled as executable PHP scripts by
the webserver.

  - Inadequate checks for access level permissions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to modify the access levels
of user groups with higher permissions and use PHAR files as executable PHP scripts.");

  script_tag(name:"affected", value:"Joomla core version 2.5.0 through 3.8.7");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.8.8 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/730-20180502-core-add-phar-files-to-the-upload-blacklist.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/729-20180501-core-acl-violation-in-access-levels.html");
  script_xref(name:"URL", value:"https://www.joomla.org");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!jPort = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:jPort, exit_no_version:TRUE )) exit(0);
jVer = infos['version'];
path = infos['location'];

if(version_in_range(version:jVer, test_version:"2.5.0", test_version2:"3.8.7")) {
  report = report_fixed_ver(installed_version:jVer, fixed_version:"3.8.8", install_path:path);
  security_message(port:jPort, data:report);
  exit(0);
}

exit(0);
