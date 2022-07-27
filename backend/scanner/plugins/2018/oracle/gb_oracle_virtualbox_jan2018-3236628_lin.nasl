###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_virtualbox_jan2018-3236628_lin.nasl 12068 2018-10-25 07:21:15Z mmartin $
#
# Oracle VirtualBox Security Updates (jan2018-3236628) - Linux
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
###############################################################################

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812642");
  script_version("$Revision: 12068 $");
  script_cve_id("CVE-2018-2688", "CVE-2018-2689", "CVE-2018-2676", "CVE-2018-2698",
                "CVE-2018-2694", "CVE-2018-2693", "CVE-2018-2685", "CVE-2018-2686",
                "CVE-2018-2687", "CVE-2018-2690", "CVE-2017-5715", "CVE-2017-3735");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 09:21:15 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-17 13:17:18 +0530 (Wed, 17 Jan 2018)");
  script_name("Oracle VirtualBox Security Updates (jan2018-3236628) - Linux");

  script_tag(name:"summary", value:"The host is installed with Oracle VM
  VirtualBox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to

  - Multiple errors in the 'Core' component of the application.

  - An error in the 'Guest Additions' component of the application.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow local attackers to gain elevated privileges on
  the host system.");

  script_tag(name:"affected", value:"VirtualBox versions prior to 5.1.32 and
  5.2.x prior to 5.2.6 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox 5.1.32 or 5.2.6
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");
  script_xref(name:"URL", value:"https://www.virtualbox.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
virtualVer = infos['version'];
path = infos['location'];

if(virtualVer =~ "^(5\.2)" && (version_is_less(version:virtualVer, test_version:"5.2.6"))){
  fix = "5.2.6";
}

else if(version_is_less(version:virtualVer, test_version:"5.1.32")){
  fix = "5.1.32";
}

if(fix){
  report = report_fixed_ver(installed_version:virtualVer, fixed_version: fix, install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
