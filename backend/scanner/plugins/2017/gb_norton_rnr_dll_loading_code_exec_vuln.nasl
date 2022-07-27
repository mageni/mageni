###############################################################################
# OpenVAS Vulnerability Test
#
# Norton Remove & Reinstall DLL Preloading Code Execution Vulnerability
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

CPE = "cpe:/a:norton:remove_%26_reinstall";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812214");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2017-13676");
  script_bugtraq_id(100939);
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2017-11-07 14:00:28 +0530 (Tue, 07 Nov 2017)");
  script_name("Norton Remove & Reinstall DLL Preloading Code Execution Vulnerability");

  script_tag(name:"summary", value:"This host is running Norton Remove & Reinstall
  and is prone to dll preloading code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to application looks to call
  a DLL for execution and an attacker provides a malicious DLL to use instead.
  Depending on how the application is configured, it will generally follow a
  specific search path to locate the DLL.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to do simple file write (or potentially an over-write) which results in a
  foreign DLL running under the context of the application.");

  script_tag(name:"affected", value:"Norton Remove & Reinstall prior to version
  4.4.0.58");

  script_tag(name:"solution", value:"Upgrade to Norton Remove & Reinstall version
  4.4.0.58 or later.");


  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20170926_00");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_norton_remove_n_reinstall_detect.nasl");
  script_mandatory_keys("Norton/Remove/Reinstall/Win/Ver");
  script_xref(name:"URL", value:"https://www.symantec.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

nrnVer = infos['version'];
nrnPath = infos['location'];

if(version_is_less(version:nrnVer, test_version:"4.4.0.58"))
{
  report = report_fixed_ver(installed_version:nrnVer, fixed_version:"4.4.0.58", install_path:nrnPath);
  security_message(data:report);
  exit(0);
}
exit(0);
