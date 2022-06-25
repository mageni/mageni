###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle BI Publisher Multiple Privilege Escalation Vulnerabilities
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

CPE = "cpe:/a:oracle:business_intelligence_publisher";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813583");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-2958", "CVE-2018-2925");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-18 14:53:36 +0530 (Wed, 18 Jul 2018)");
  ## Not sure about version upgradation after patch applied
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Oracle BI Publisher Multiple Privilege Escalation Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Oracle BI Publisher
  and is prone to multiple privilege escalation vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to unspecified
  errors in Security component and Web Server component.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to escalate privileges and gain unauthorized rights to access and modify data.");

  script_tag(name:"affected", value:"Oracle BI Publisher versions 11.1.1.7.0,
  11.1.1.9.0, 12.2.1.2.0, 12.2.1.3.0");

  script_tag(name:"solution", value:"Apply the appropriate patch from the below
  mentioned Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html#AppendixFMW");
  script_xref(name:"URL", value:"http://www.oracle.com");
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

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE, port:obpPort)) exit(0);
obpVer = infos['version'];
obPath = infos['location'];

affected = make_list( "11.1.1.7.0", "11.1.1.9.0", "12.2.1.2.0", "12.2.1.3.0");

foreach af ( affected )
{
  if( obpVer == af )
  {
    report = report_fixed_ver(installed_version:obpVer, fixed_version:"Apply Patch", install_path:obPath);
    security_message(data:report, port:obpPort);
    exit(0);
  }
}

exit(0);
