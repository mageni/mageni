###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ip_phone_cisco-sa-20171115-ipp.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco IP Phone 8800 Series Command Injection Vulnerability in Debug Shell
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.140503");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-16 09:53:34 +0700 (Thu, 16 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-12305");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco IP Phone 8800 Series Command Injection Vulnerability in Debug Shell");

  script_category(ACT_GATHER_INFO);

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_ip_phone_detect.nasl");
  script_mandatory_keys("cisco/ip_phone/model");

  script_tag(name:"summary", value:"A vulnerability in the debug interface of Cisco IP Phone 8800 series could
allow an authenticated, local attacker to execute arbitrary commands.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation.");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by authenticating to the device
and submitting additional command input to the affected parameter in the debug shell.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171115-ipp");

  exit(0);
}

include("version_func.inc");

if (!model = get_kb_item("cisco/ip_phone/model"))
  exit(0);

if (model =~ "^CP-88..") {
  if (!version = get_kb_item("cisco/ip_phone/version"))
    exit(0);

  version = eregmatch(pattern: "sip88xx\.([0-9-]+)", string: version);
  if (!isnull(version[1])) {
    version = ereg_replace(string: version[1], pattern: "-", replace: ".");
    if (version_is_less(version: version, test_version: "11.1.1MPP502")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "11.1.1MPP502");
      security_message(port: 0, data: report);
      exit(0);
    }
    if (version =~ "^12\.") {
      if (version_is_less(version: version, test_version: "12.1.1MN92")) {
        report = report_fixed_ver(installed_version: version, fixed_version: "12.1.1MN92");
        security_message(port: 0, data: report);
        exit(0);
      }
    }
  }
}

exit(0);
