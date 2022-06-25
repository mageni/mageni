###############################################################################
# OpenVAS Vulnerability Test
#
# ClamAV Multiple Vulnerabilities July18 (Windows)
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

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813577");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-0360", "CVE-2018-0361");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-17 13:50:22 +0530 (Tue, 17 Jul 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ClamAV Multiple Vulnerabilities July18 (Windows)");

  script_tag(name:"summary", value:"This host is installed with ClamAV and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A lack PDF object length check.

  - HWP integer overflow error in function 'parsehwp3_paragraph' in file
    libclamav/hwp.c.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause denial of service and lengthen file parsing time.");

  script_tag(name:"affected", value:"ClamAV version before 0.100.1 on Windows");

  script_tag(name:"solution", value:"Update to version 0.100.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://blog.clamav.net/2018/07/clamav-01001-has-been-released.html");
  script_xref(name:"URL", value:"https://secuniaresearch.flexerasoftware.com/secunia_research/2018-12/");
  script_xref(name:"URL", value:"https://www.clamav.net/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_clamav_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ClamAV/remote/Ver", "Host/runs_windows");
  script_require_ports(3310);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!clamPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:clamPort, exit_no_version:TRUE)) exit(0);
clamVer = infos['version'];
path = infos['location'];

if(version_is_less(version:clamVer, test_version:"0.100.1"))
{
  report = report_fixed_ver(installed_version:clamVer, fixed_version:"0.100.1", install_path:path);
  security_message(data:report, port:clamPort);
  exit(0);
}

exit(99);
