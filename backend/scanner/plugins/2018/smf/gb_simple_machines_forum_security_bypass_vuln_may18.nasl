###############################################################################
# OpenVAS Vulnerability Test
#
# Simple Machines Forum Security Bypass Vulnerability May18
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

CPE = "cpe:/a:simplemachines:smf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812886");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-10305");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-14 16:42:36 +0530 (Mon, 14 May 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Simple Machines Forum Security Bypass Vulnerability May18");

  script_tag(name:"summary", value:"This host is running Simple Machines Forum and is
  prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the 'MessageSearch2' function
  in PersonalMessage.php script in Simple Machines Forum (SMF) does not properly use
  the 'possible_users' variable in a query.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to bypass intended access restrictions.");

  script_tag(name:"affected", value:"Simple Machines Forum versions before 2.0.15");

  script_tag(name:"solution", value:"Upgrade to Simple Machines Forum version
  2.0.15 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.simplemachines.org/community/index.php?topic=557176.0");
  script_xref(name:"URL", value:"https://download.simplemachines.org/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_detect.nasl");
  script_mandatory_keys("SMF/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!sport = get_app_port(cpe: CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:sport, exit_no_version:TRUE)) exit(0);
sver = infos['version'];
spath = infos['location'];

if(version_is_less( version: sver, test_version: "2.0.15"))
{
  report = report_fixed_ver(installed_version:sver, fixed_version:"2.0.15", install_path:spath);
  security_message(port:sport, data:report);
  exit(0);
}
exit(0);
