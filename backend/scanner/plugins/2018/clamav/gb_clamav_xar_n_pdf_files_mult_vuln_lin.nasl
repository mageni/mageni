###############################################################################
# OpenVAS Vulnerability Test
#
# ClamAV 'PDF' and 'XAR Files Parsing Multiple Vulnerabilities (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812578");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-0202", "CVE-2018-1000085");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-03-21 11:16:51 +0530 (Wed, 21 Mar 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ClamAV 'PDF' and 'XAR Files Parsing Multiple Vulnerabilities (Linux)");

  script_tag(name:"summary", value:"This host is installed with ClamAV and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An incorrectly handled parsing certain PDF files and

  - An incorrectly handled parsing certain XAR files.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause a denial of service and potentially execute arbitrary code
  on the affected device.");

  script_tag(name:"affected", value:"ClamAV version 0.99.3 and prior on Linux.");

  script_tag(name:"solution", value:"Update to version 0.99.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://github.com/Cisco-Talos/clamav-devel/commit/d96a6b8bcc7439fa7e3876207aa0a8e79c8451b6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_clamav_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ClamAV/remote/Ver", "Host/runs_unixoide");
  script_require_ports(3310);
  script_xref(name:"URL", value:"https://www.clamav.net/downloads");
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

if(version_is_less(version:clamVer, test_version:"0.99.4"))
{
  report = report_fixed_ver(installed_version:clamVer, fixed_version:"0.99.4", install_path:path);
  security_message(data:report, port:clamPort);
  exit(0);
}
