###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ip_phone_buffer_overflow_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Cisco IP Phone 8800 Series Web Application Buffer Overflow Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106111");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-27 14:59:12 +0700 (Mon, 27 Jun 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2016-1421");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco IP Phone 8800 Series Web Application Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_ip_phone_detect.nasl");
  script_mandatory_keys("cisco/ip_phone/model");

  script_tag(name:"summary", value:"Cisco IP Phone 8800 Series are prone to a buffer overflow vulnerability");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists because the affected software fails to check
the bounds of input data. An attacker could exploit this vulnerability by sending a malicious request to
the web server, which could cause the service to crash.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to trigger a buffer
overflow and create a DoS condition on the targeted system.");

  script_tag(name:"affected", value:"Cisco IP Phone 8800 Series phones running Release 11.0(1)");

  script_tag(name:"solution", value:"Update to Release 11.5(1) or later");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160609-ipp");

  exit(0);
}

include("version_func.inc");

if (!model = get_kb_item("cisco/ip_phone/model"))
  exit(0);

if (model =~ "^CP-88..") {
  if (!version = get_kb_item("cisco/ip_phone/version"))
    exit(0);

  version = eregmatch(pattern: "sip88xx\.([0-9-]+)", string: version);
  if (version[1] && version[1] =~ "^11-0-1") {
    report = report_fixed_ver(installed_version: version[1], fixed_version: "11-5-1");
    security_message(port: 0, data: report);
  }
}

exit(0);
