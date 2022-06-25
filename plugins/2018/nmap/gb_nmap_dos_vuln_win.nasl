###############################################################################
# OpenVAS Vulnerability Test
#
# Nmap Denial of Service Vulnerability (Windows)
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

CPE = "cpe:/a:nmap:nmap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813825");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-15173");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-14 12:02:26 +0530 (Tue, 14 Aug 2018)");

  script_name("Nmap Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Nmap
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exist due to -sV option usage and
  an improper validation for a crafted TCP-based service via an unknown function
  of the component TCP Connection Handler.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause stack consumption leading to denial of service condition.");

  script_tag(name:"affected", value:"Nmap versions 7.70 and prior on Windows.");

  script_tag(name:"solution", value:"No known solution is available as of 11th March, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://code610.blogspot.com/2018/07/crashing-nmap-770.html");
  script_xref(name:"URL", value:"https://nmap.org");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_nmap_detect_win.nasl");
  script_mandatory_keys("Nmap/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
nmapVer = infos['version'];
nmappath = infos['location'];

if(version_is_less_equal(version:nmapVer, test_version:"7.70")) {
  report = report_fixed_ver(installed_version:nmapVer, fixed_version:"None", install_path:nmappath);
  security_message(data:report);
  exit(0);
}

exit(0);
