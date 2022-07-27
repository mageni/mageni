###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tika Server Java Code Execution Vulnerability
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
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

CPE = "cpe:/a:apache:tika";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813537");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2016-6809");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-06-20 17:03:55 +0530 (Wed, 20 Jun 2018)");
  script_name("Apache Tika Server Java Code Execution Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Apache Tika Server
  and is prone to arbitrary Java code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Apache Tika Server
  invoking JMatIO to do native deserialization.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary Java code for serialized objects embedded in
  MATLAB files.");

  script_tag(name:"affected", value:"Apache Tika Server from versions 1.6 to 1.13");

  script_tag(name:"solution", value:"Upgrade to Apache Tika Server 1.14 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/93618b15cdf3b38fa1f0bfc0c8c7cf384607e552935bd3db2e322e07@%3Cdev.tika.apache.org%3E");
  script_xref(name:"URL", value:"https://tika.apache.org");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_server_detect.nasl");
  script_mandatory_keys("Apache/Tika/Server/Installed");
  script_require_ports("Services/www", 9998, 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!tPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:tPort, exit_no_version:TRUE)) exit(0);
tVer = infos['version'];
tPath = infos['location'];

if(version_in_range(version:tVer, test_version: "1.6", test_version2: "1.13"))
{
  report = report_fixed_ver(installed_version:tVer, fixed_version:"1.14", install_path:tPath);
  security_message(data:report, port:tPort);
  exit(0);
}
exit(0);
