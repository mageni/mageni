###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_dcerpcnt_dos_vuln_nov09_lin.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Wireshark 'DCERPC/NT' Dissector DOS Vulnerability - Nov09 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:wireshark:wireshark';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801035");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-11-04 07:03:36 +0100 (Wed, 04 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3550");
  script_bugtraq_id(36846);
  script_name("Wireshark 'DCERPC/NT' Dissector DOS Vulnerability - Nov09 (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("Wireshark/Linux/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37175");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54016");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3689");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.3.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.0.10.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2009-07.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2009-08.html");

  script_tag(name:"impact", value:"Successful exploitation could result in Denial of service condition.");

  script_tag(name:"affected", value:"Wireshark version 0.10.13 to 1.0.9 and 1.2.0 to 1.2.2 on Linux.");

  script_tag(name:"insight", value:"The flaw is due to a NULL pointer dereference error within the 'DCERPC/NT'
  dissector that can be exploited to cause a crash.");

  script_tag(name:"solution", value:"Upgrade to Wireshark 1.0.10 or 1.2.3.

  Workaround: Disable the affected dissectors.");
  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to Denial of
  Service Vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ver = get_app_version(cpe:CPE)) exit(0);

if(version_in_range(version:ver, test_version:"1.2.0", test_version2:"1.2.2") ||
   version_in_range(version:ver, test_version:"0.10.13", test_version2:"1.0.9")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"1.0.10/1.2.3");
  security_message(data:report);
  exit(0);
}

exit(99);