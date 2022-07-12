###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_appli_manager_mult_sql_inj_vuln.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# ManageEngine Applications Manager Multiple SQL Injections Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:manageengine:applications_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812231");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2017-16846", "CVE-2017-16847", "CVE-2017-16848", "CVE-2017-16849",
                "CVE-2017-16850", "CVE-2017-16851");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-29 18:51:22 +0530 (Wed, 29 Nov 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ManageEngine Applications Manager Multiple SQL Injections Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with ManageEngine
  Applications Manager and is prone to multiple sql injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to multiple input
  validation errors via,

  - 'method' parameter in '/manageApplications.do' script,

  - 'resourceid' parameter in '/showresource.do' script,

  - 'groupname' parameter in '/manageConfMons.do' script,

  - 'method' parameter in ' /MyPage.do' script,

  - 'resourceid' parameter in '/showresource.do' script,

  - 'widgetid' parameter in '/MyPage.do' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to execute arbitrary sql commands.");

  script_tag(name:"affected", value:"ManageEngine Applications Manager 13.");

  script_tag(name:"solution", value:"Update to version 13530 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://code610.blogspot.in/2017/11/more-sql-injections-in-manageengine.html");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_appli_manager_detect.nasl");
  script_mandatory_keys("ManageEngine/Applications/Manager/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!manport = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:manport, exit_no_version:TRUE)) exit(0);
manVer = infos['version'];
manpath = infos['location'];

if(manVer =~ "^13")
{
  if(version_is_less(version: manVer, test_version: "13530"))
  {
    report = report_fixed_ver(installed_version: manVer, fixed_version: "13530", install_path:manpath);
    security_message(port: manport, data: report);
    exit(0);
  }
}

exit(0);
