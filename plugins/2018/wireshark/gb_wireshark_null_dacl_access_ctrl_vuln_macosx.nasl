###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark 'non-NULL DACL' Access Control Vulnerability (Mac OS X)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
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

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813591");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-14438");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-30 16:58:30 +0530 (Mon, 30 Jul 2018)");

  script_name("Wireshark 'non-NULL DACL' Access Control Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to create_app_running_mutex
  function in wsutil/file_util.c calling SetSecurityDescriptorDacl to set
  a NULL DACL.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to modify the access control arbitrarily.");

  script_tag(name:"affected", value:"Wireshark version through 2.6.6 on Mac OS X.");

  script_tag(name:"solution", value:"No known solution is available as of 18th February, 2019.
  Information regarding this issue will be updated once solution details are available. Please see the references for more information.");

  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=14921");
  script_xref(name:"URL", value:"https://www.wireshark.org");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
wirversion = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:wirversion, test_version:"2.6.6")){
  report = report_fixed_ver(installed_version:wirversion, fixed_version:"NoneAvailable", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);