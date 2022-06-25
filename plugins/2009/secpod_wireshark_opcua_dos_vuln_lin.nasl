###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wireshark_opcua_dos_vuln_lin.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Wireshark OpcUa Dissector Denial of Service Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901032");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-3241");
  script_bugtraq_id(36408);
  script_name("Wireshark OpcUa Dissector Denial of Service Vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("Wireshark/Linux/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36754");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2009-06.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2009-05.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3986");

  script_tag(name:"impact", value:"Successful exploitation could result in Denial of service condition.");

  script_tag(name:"affected", value:"Wireshark version 0.99.6 to 1.0.8, 1.2.0 to 1.2.1 on Linux.");

  script_tag(name:"insight", value:"The flaw is due to unspecified error in 'OpcUa' dissector which can be
  exploited by sending malformed OPCUA Service CallRequest packets.");

  script_tag(name:"solution", value:"Upgrade to Wireshark 1.0.9 or 1.2.2.");

  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to Denial of
  Service vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ver = get_app_version(cpe:CPE)) exit(0);

# Alert for Wireshark version 0.96.6 to 1.0.8 and 1.2.0 to 1.2.1
if(version_in_range(version:ver, test_version:"0.99.6", test_version2:"1.0.8")||
   version_in_range(version:ver, test_version:"1.2.0", test_version2:"1.2.1")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"1.0.9 or 1.2.2");
  security_message(data:report);
  exit(0);
}

exit(99);