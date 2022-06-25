###############################################################################
# OpenVAS Vulnerability Test
#
# Intel Active Management Technology Buffer Overflow And Memory Corruption Vulnerabilities
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

CPE = 'cpe:/h:intel:active_management_technology';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813800");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-3628", "CVE-2018-3629", "CVE-2018-3632");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-24 13:43:57 +0530 (Tue, 24 Jul 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Intel Active Management Technology Buffer Overflow And Memory Corruption Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Intel Active
  Management Technology and is prone to multiple buffer overflow and memory
  corruption vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple unspecified
  buffer overflow and memory corruption errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, cause a denial of service via the same subnet and also
  gain elevated privileges on the system.");

  script_tag(name:"affected", value:"Intel Active Management Technology versions
  3.x/4.x/5.x/6.x/7.x/8.x/9.x/10.x/11.x.");

  script_tag(name:"solution", value:"Upgrade to appropriate Intel CSME firmware
  version. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00112.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_intel_amt_webui_detect.nasl");
  script_mandatory_keys("intel_amt/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!imePort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location( cpe:CPE, port:imePort, exit_no_version:TRUE)) exit(0);
imeVer = infos['version'];
imepath = infos['location'];

if(imeVer =~ "^((3|4|5|6|7|8|9|10|11)\.)")
{
  report = report_fixed_ver(installed_version:imeVer, fixed_version:"Upgrade to appropriate Intel CSME firmware version as mentioned in reference link", install_path:imepath);
  security_message(port:imePort, data:report);
  exit(0);
}
exit(0);
