# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814687");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2019-7091", "CVE-2019-7092");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2019-02-14 12:03:46 +0530 (Thu, 14 Feb 2019)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe ColdFusion Code Execution And Information Disclosure Vulnerabilities (APSB19-10)");

  script_tag(name:"summary", value:"This host is running Adobe ColdFusion and is
  prone to code execution and information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to an improper validation
  and deserialization of untrusted data.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the affected application
  and disclose sensitive information.");

  script_tag(name:"affected", value:"Adobe ColdFusion version 11 before Update 16");

  script_tag(name:"solution", value:"Upgrade to Adobe ColdFusion 11 Update 16 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.adobe.com/products/coldfusion/download-trial/try.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb19-10.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_coldfusion_detect.nasl");
  script_mandatory_keys("coldfusion/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!cfPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:cfPort, exit_no_version:TRUE)) exit(0);
cfdVer = infos['version'];
cfdPath = infos['location'];

##https://helpx.adobe.com/in/coldfusion/kb/coldfusion-11-updates.html
if(version_in_range(version:cfdVer, test_version:"11.0", test_version2:"11.0.15.307976"))
{
  report = report_fixed_ver(installed_version:cfdVer, fixed_version:"ColdFusion 11 Update 16", install_path:cfdPath);
  security_message(data:report, port:cfPort);
  exit(0);
}
exit(99);
