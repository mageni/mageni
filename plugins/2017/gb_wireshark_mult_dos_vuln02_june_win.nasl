###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_dos_vuln02_june_win.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# Wireshark Multiple Denial-of-Service Vulnerabilities-02 June17 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811072");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2017-9348", "CVE-2017-9347", "CVE-2017-9353");
  script_bugtraq_id(98801, 98800, 98805);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-06-02 16:48:52 +0530 (Fri, 02 Jun 2017)");
  script_name("Wireshark Multiple Denial-of-Service Vulnerabilities-02 June17 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An error in the epan/dissectors/packet-ipv6.c script within the IPv6
    dissector which could crash.

  - An error in the epan/dissectors/asn1/ros/packet-ros-template.c script within
    the ROS dissector which could crash with a NULL pointer dereference.

  - An error in the epan/dissectors/packet-dof.c script within the DOF dissector
    which could read past the end of a buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to crash wireshark and result in denial-of-service condition.");

  script_tag(name:"affected", value:"Wireshark version 2.2.0 through 2.2.6
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.2.7 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-23.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-31.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-33.html");

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

if(wirversion =~ "^(2\.2)" && version_is_less(version:wirversion, test_version:"2.2.7"))
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:"2.2.7");
  security_message(data:report);
  exit(0);
}