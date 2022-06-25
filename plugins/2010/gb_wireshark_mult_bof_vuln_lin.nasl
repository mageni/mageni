###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_bof_vuln_lin.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Wireshark Multiple Buffer Overflow Vulnerabilities (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800289");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-02-08 10:53:20 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0304");
  script_bugtraq_id(37985);
  script_name("Wireshark Multiple Buffer Overflow Vulnerabilities (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_family("Buffer overflow");
  script_mandatory_keys("Wireshark/Linux/Ver");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55951");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37985/info");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0239");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to crash an affected application or
  potentially execute arbitrary code.");
  script_tag(name:"affected", value:"Wireshark version 1.2.0 to 1.2.5 and 0.9.15 to 1.0.10");
  script_tag(name:"insight", value:"The flaws are caused by buffer overflow errors in the LWRES dissector when
  processing malformed data or packets.");
  script_tag(name:"solution", value:"Upgrade to Wireshark 1.2.6 or 1.0.11");
  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to multiple Buffer
  Overflow vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.wireshark.org/download.html");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ver = get_app_version(cpe:CPE)) exit(0);

if(version_in_range(version:ver, test_version:"1.2.0", test_version2:"1.2.5") ||
   version_in_range(version:ver, test_version:"0.9.15", test_version2:"1.0.10")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"1.0.11/1.2.6");
  security_message(data:report);
  exit(0);
}

exit(99);