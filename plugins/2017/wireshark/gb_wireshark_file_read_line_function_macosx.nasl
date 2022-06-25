###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark 'File_read_line' Function Denial of Service Vulnerability (Mac OS X)
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

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812282");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2017-17935");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2017-12-28 12:52:35 +0530 (Thu, 28 Dec 2017)");
  script_name("Wireshark 'File_read_line' Function Denial of Service Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a buffer underflow
  error in 'File_read_line' function in 'epan/wslua/wslua_file.c' file.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to cause a denial of service.");

  script_tag(name:"affected", value:"Wireshark version through 2.2.11 on
  Mac OS X.");

  script_tag(name:"solution", value:"Update Wireshark to version 2.2.12 or later.");

  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=14295");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.2.12.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

wirversion = "";
path = "";
infos = "";

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
wirversion = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:wirversion, test_version:"2.2.11"))
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:"2.2.12", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
