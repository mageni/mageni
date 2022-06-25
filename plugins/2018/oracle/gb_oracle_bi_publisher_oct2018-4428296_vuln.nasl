###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle BI Publisher Code Execution Vulnerability (oct2018-4428296)
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

CPE = "cpe:/a:oracle:business_intelligence_publisher";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814409");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2017-5645");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-10-18 16:42:53 +0530 (Thu, 18 Oct 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle BI Publisher Code Execution Vulnerability (oct2018-4428296)");

  script_tag(name:"summary", value:"This host is installed with Oracle BI Publisher
  and is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Check if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exist due to an unspecified
  error in BI Publisher Security (Apache Log4j) component.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Oracle BI Publisher versions 11.1.1.7.0,
  11.1.1.9.0, 12.2.1.3.0 and 12.2.1.4.0");

  script_tag(name:"solution", value:"Apply the latest patch from vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_bi_publisher_detect.nasl");
  script_mandatory_keys("Oracle/BI/Publisher/Enterprise/installed");
  script_require_ports("Services/www", 9704);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!obpPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:obpPort, exit_no_version:TRUE)) exit(0);
obpVer = infos['version'];
path = infos['location'];

affected = make_list('11.1.1.7.0', '11.1.1.9.0', '12.2.1.3.0', '12.2.1.4.0');
foreach version (affected)
{
  if(obpVer == version)
  {
    report = report_fixed_ver(installed_version:obpVer, fixed_version: "Apply the patch", install_path:path);
    security_message(port:obpPort, data:report);
    exit(0);
  }
}
exit(99);
