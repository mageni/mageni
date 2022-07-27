###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dameware_mini_rc_bof_vuln.nasl 13699 2019-02-15 14:29:50Z cfischer $
#
# DameWare Mini Remote Control < 12.1 Buffer Overflow Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.107379");
  script_version("$Revision: 13699 $");
  script_cve_id("CVE-2018-12897");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 15:29:50 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-11-24 13:15:04 +0100 (Sat, 24 Nov 2018)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("DameWare Mini Remote Control < 12.1 Buffer Overflow Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_dameware_mini_rc_detect_win.nasl");
  script_mandatory_keys("dameware/mini_remote_control/win/detected");

  script_tag(name:"summary", value:"DameWare Mini Remote Control is prone to a local buffer overflow vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw exists due to insecure handling of a user input buffer which ultimately allows
  for overwriting Structured Exception Handler (SEH) addresses and the subsequent hijacking of execution flow.");
  script_tag(name:"impact", value:"Successful exploitation will allow local attackers to conduct buffer overflow attacks on the affected system.");
  script_tag(name:"affected", value:"DameWare Mini Remote Control before version 12.1.");
  script_tag(name:"solution", value:"Upgrade DameWare Mini Remote Control to version 12.1 or later.");

  script_xref(name:"URL", value:"https://labs.nettitude.com/blog/solarwinds-cve-2018-12897-dameware-mini-remote-control-local-seh-buffer-overflow/");

  exit(0);
}

CPE = "cpe:/a:dameware:mini_remote_control";

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) {
  exit (0);
}

vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"12.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
