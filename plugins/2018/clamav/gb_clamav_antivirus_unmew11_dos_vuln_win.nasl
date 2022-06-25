###############################################################################
# OpenVAS Vulnerability Test
#
# Clam AntiVirus 'unmew11()' Denial of Service Vulnerability (Windows)
#
# Authors:
# Antu Saandi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.814146");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-15378");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-10-17 14:57:50 +0530 (Wed, 17 Oct 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Clam AntiVirus 'unmew11()' Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with ClamAV and is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw related to the MEW unpacker within
  the 'unmew11()' function (libclamav/mew.c) can be exploited to trigger an
  invalid read memory access via a specially crafted EXE file.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attackers
  to cause denial of service.");

  script_tag(name:"affected", value:"ClamAV AntiVirus versions before 0.100.2 on Windows.");

  script_tag(name:"solution", value:"Update to version 0.100.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.clamav.net/show_bug.cgi?id=12170");
  script_xref(name:"URL", value:"https://www.clamav.net");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
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

if(version_is_less(version:clamVer, test_version:"0.100.2"))
{
  report = report_fixed_ver(installed_version:clamVer, fixed_version:"0.100.2", install_path:path);
  security_message(data:report, port:clamPort);
  exit(0);
}
exit(99);
