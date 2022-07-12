###############################################################################
# OpenVAS Vulnerability Test
#
# Intel Management Engine Privilege Escalation And Buffer Overflow Vulnerabilities
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

CPE = 'cpe:/h:intel:management_engine';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812221");
  script_version("2019-05-17T13:14:58+0000");
  script_cve_id("CVE-2017-5705", "CVE-2017-5708");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 13:14:58 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2017-11-22 13:16:37 +0530 (Wed, 22 Nov 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Intel Management Engine Privilege Escalation And Buffer Overflow Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with
  Intel Management Engine and is prone to privilege escalation and buffer
  overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple unspecified
  buffer overflow and privilege escalation errors in kernel.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  with local access to the system to execute arbitrary code and allow
  unauthorized process to access privileged content via unspecified vector.");

  script_tag(name:"affected", value:"Systems using Intel ME Firmware
  versions 11.0.x.x/11.5.x.x/11.6.x.x/11.7.x.x/11.10.x.x/11.20.x.x.");

  script_tag(name:"solution", value:"Upgrade Intel ME to appropriate
  firmware version as mentioned in the link below.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://thehackernews.com/2017/11/intel-chipset-flaws.html");
  script_xref(name:"URL", value:"https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00086&languageid=en-fr");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_intel_management_engine_detect.nasl");
  script_mandatory_keys("intel_me/installed");
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

if(imeVer =~ "^11\.(0|5|6|7|10|20)")
{
  report = report_fixed_ver(installed_version:imeVer, fixed_version:"Upgrade to appropriate Intel ME firmware version as mentioned in reference link", install_path:imepath);
  security_message(port:imePort, data:report);
  exit(0);
}
exit(0);
