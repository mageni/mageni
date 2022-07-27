###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openvpn_win_dos_vuln.nasl 13699 2019-02-15 14:29:50Z cfischer $
#
# OpenVPN 2.4.x < 2.4.6 DoS Vulnerability (Windows)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107310");
  script_version("$Revision: 13699 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 15:29:50 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-05-11 09:50:01 +0200 (Fri, 11 May 2018)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_cve_id("CVE-2018-9336");
  script_name("OpenVPN 2.4.x < 2.4.6 DoS Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openvpn_win_detect.nasl");
  script_mandatory_keys("OpenVPN/Win/Ver");
  script_tag(name:"summary", value:"OpenVPN is prone to a Denial of Service vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"openvpnserv.exe (aka the interactive service helper) in OpenVPN 2.4.x before
  2.4.6 allows a local attacker to cause a double-free of memory by sending a malformed request to the interactive
  service. This could cause a denial-of-service through memory corruption or possibly have unspecified other impact
  including privilege escalation.");
  script_tag(name:"affected", value:"OpenVPN version 2.4.x before 2.4.6.");
  script_tag(name:"solution", value:"Upgrade to OpenVPN version 2.4.6 or later.");
  script_xref(name:"URL", value:"https://community.openvpn.net/openvpn/wiki/ChangesInOpenvpn24");

  exit(0);
}

CPE = "cpe:/a:openvpn:openvpn";

include ("host_details.inc");
include ("version_func.inc");

if (!infos = get_app_version_and_location (cpe:CPE, exit_no_version:TRUE)) {
  exit (0);
}
vers = infos ['version'];
path = infos ['location'];

if (vers =~ "^2\.4\." && version_is_less (version:vers, test_version:"2.4.6")){
  report = report_fixed_ver (installed_version:vers, fixed_version:"2.4.6", install_path:path);
  security_message (port:0, data:report);
  exit (0);
}

exit (99);
