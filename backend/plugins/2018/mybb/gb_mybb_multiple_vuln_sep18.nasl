###############################################################################
# OpenVAS Vulnerability Test
#
# MyBB Multiple Vulnerabilities-Sep 2018
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:mybb:mybb";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.814216");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-17128");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-09-18 16:04:20 +0530 (Tue, 18 Sep 2018)");
  script_name("MyBB Multiple Vulnerabilities-Sep 2018");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The host is installed with MyBB and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Insufficient permission check in User CP's attachment management.

  - Insufficient email address verification.

  - Insufficient validation of input in Visual Editor and Email field.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct SQL Injection, execute arbitrary javascript code and
  gain escalated privilege.");

  script_tag(name:"affected", value:"MyBB versions prior to 1.8.19");

  script_tag(name:"solution", value:"Upgrade MyBB to version 1.8.19 or later. Please see the references for more information.");

  script_xref(name:"URL", value:"https://mybb.com/versions/1.8.19");
  script_xref(name:"URL", value:"https://mybb.com");
  script_xref(name:"URL", value:"https://blog.mybb.com/2018/09/11/mybb-1-8-19-released-security-maintenance-release");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_mandatory_keys("MyBB/installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE )) exit(0);
version = infos['version'];
path = infos['location'];

if(version_is_less(version:version, test_version:"1.8.19"))
{
  report = report_fixed_ver(installed_version:version, fixed_version:"1.8.19", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}
exit(0);
