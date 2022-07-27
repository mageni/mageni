###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nomachine_for_windows_rce_vuln.nasl 12590 2018-11-30 07:32:04Z asteins $
#
# NoMachine for Windows Trojan File Remote Code Execution Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.107372");
  script_version("$Revision: 12590 $");
  script_cve_id("CVE-2018-17890");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 08:32:04 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-19 15:08:42 +0100 (Mon, 19 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("NoMachine for Windows Trojan File Remote Code Execution Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_nomachine_for_windows_detect.nasl");
  script_mandatory_keys("nomachine/win/detected");

  script_tag(name:"summary", value:"NoMachine for Windows <= version 5.3.26 or < 6.3.6 is prone to a Trojan File Remeote Code Execution vulnerability.");

  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Possible arbitrary code execution when opening a '.nxs' nomachine file type on client's wintab32.dll preload.

This issue regards the client part of all NoMachine installations on Windows (NoMachine free, NoMachine Enterprise Client,

NoMachine Enteprise Desktop and NoMachine Cloud Server).");

  script_tag(name:"affected", value:"NoMachine for Windows <= 5.3.26 or < 6.3.6.");

  script_tag(name:"solution", value:"Upgrade to NoMachine for Windows version 5.3.27, 6.3.6 or later.");

  script_xref(name:"URL", value:"http://hyp3rlinx.altervista.org/advisories/NOMACHINE-TROJAN-FILE-REMOTE-CODE-EXECUTION.txt");
  script_xref(name:"URL", value:"https://www.nomachine.com/SU10P00199");
  script_xref(name:"URL", value:"https://www.nomachine.com/SU10P00200");

  exit(0);
}

CPE = "cpe:/a:nomachine:nomachine";

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) {
  exit (0);
}

vers = infos['version'];
path = infos['location'];

if (version_is_less (version:vers, test_version:"5.3.27")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.3.27", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}
if (version_in_range (version:vers, test_version: "6.0.0", test_version2: "6.3.5")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.3.6", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
