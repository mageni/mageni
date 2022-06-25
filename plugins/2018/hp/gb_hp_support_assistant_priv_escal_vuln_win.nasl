###############################################################################
# OpenVAS Vulnerability Test
#
# HP Support Assistant Privilege Escalation Vulnerability (Windows)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##########################################################################

CPE = "cpe:/a:hp:support_assistant";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812945");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2017-2744");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-02-23 11:48:49 +0530 (Fri, 23 Feb 2018)");
  script_name("HP Support Assistant Privilege Escalation Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with HP Support
  Assistant and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some unspecified
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to gain escalated privileges and extract binaries into protected file system
  locations.");

  script_tag(name:"affected", value:"HP Support Assistant 8 with framework version
  prior to 12.7.26.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to latest HP Support Assistant with
  framework version 12.7.26.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/c05648974");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_support_assistant_detect.nasl");
  script_mandatory_keys("HP/Support/Assistant/Win/Ver", "HP/Support/Assistant/FW/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!frameVer = get_app_version(cpe:"cpe:/a:hp:support_solution_framework")){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE )) exit(0);
hpvers = infos['version'];
path = infos['location'];

if(hpvers =~ "^8")
{
  if(version_is_less(version:frameVer, test_version:"12.7.26.1"))
  {
    report = report_fixed_ver(installed_version:"Assistant " + hpvers + " with Framework " + frameVer, fixed_version:"Apply updates from vendor", install_path:path);
    security_message(data:report);
    exit(0);
  }
}
exit(0);
