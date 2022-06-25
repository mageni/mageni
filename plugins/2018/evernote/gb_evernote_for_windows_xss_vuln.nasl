###############################################################################
# OpenVAS Vulnerability Test
#
# Evernote for Windows Stored Cross-Site Scripting Vulnerability (Windows)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107370");
  script_version("2019-05-16T07:59:11+0000");
  script_cve_id("CVE-2018-18524");
  script_tag(name:"last_modification", value:"2019-05-16 07:59:11 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-17 13:01:31 +0100 (Sat, 17 Nov 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Evernote for Windows Stored Cross-Site Scripting Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_evernote_for_windows_detect.nasl");
  script_mandatory_keys("evernote/win/detected");

  script_xref(name:"URL", value:"https://nakedsecurity.sophos.com/2018/11/07/serious-xss-flaw-discovered-in-evernote-for-windows-update-now/");

  script_tag(name:"summary", value:"Evernote for Windows through version 6.16.1 beta is prone to a Stored Cross-Site Scripting vulnerability.");

  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is caused by insufficient data validation. Input that should be handled as data is treated as code
  because it does not remove or escape special characters in the filenames of pictures embedded in notes.");

  script_tag(name:"impact", value:"Attackers could exploit Evernote notes by embedding code into filenames. When the note is opened, the code will run.");

  script_tag(name:"affected", value:"Evernote for Windows - through 6.16.1 beta.");

  script_tag(name:"solution", value:"Upgrade to Evernote for Windows version 6.16.1 beta or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:evernote:evernote";

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) {
  exit(0);
}

vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"6.16.1")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.16.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);