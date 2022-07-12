###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_dof_dissector_dos_vuln_win.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# Wireshark 'DOF dissector' DoS Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811003");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2017-7704");
  script_bugtraq_id(97634);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-19 15:33:39 +0530 (Wed, 19 Apr 2017)");
  script_name("Wireshark 'DOF dissector' DoS Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the 'DOF dissector'
  could go into an infinite loop, triggered by packet injection or a malformed
  capture file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the application to enter an infinite loop which may cause
  denial-of-service condition.");

  script_tag(name:"affected", value:"Wireshark version 2.2.0 through 2.2.5
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.2.6 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-17.html");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

if(wirversion =~ "^(2\.2)")
{
  if(version_in_range(version:wirversion, test_version:"2.2.0", test_version2:"2.2.5"))
  {
    report = report_fixed_ver(installed_version:wirversion, fixed_version:"2.2.6");
    security_message(data:report);
    exit(0);
  }
}
