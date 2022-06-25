###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ip_phone_cisco-sa-20160817-ipp.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Cisco IP Phone 8800 Series Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106188");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-18 15:00:49 +0700 (Thu, 18 Aug 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2016-1479");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco IP Phone 8800 Series Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_ip_phone_detect.nasl");
  script_mandatory_keys("cisco/ip_phone/model");

  script_tag(name:"summary", value:"A vulnerability in the web server of the Cisco IP Phone 8800 Series
could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper validation of user-supplied input
by the affected software. An attacker could exploit this vulnerability by sending a malicious HTTP request to
the affected device.");

  script_tag(name:"impact", value:"A successful exploit could cause memory corruption that results in a
DoS condition.");

  script_tag(name:"affected", value:"Cisco IP Phone 8800 Series version 11.0(1) is affected");

  script_tag(name:"solution", value:"Update to Release 11.7(1)MN367 or later.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-ipp");

  exit(0);
}

include("version_func.inc");

if (!model = get_kb_item("cisco/ip_phone/model"))
  exit(0);

if (model =~ "^CP-88..") {
  if (model =~ "^CP-8831" || model =~ "^CP-8821" || model =~ "^CP-8825")
    exit(0);

  if (!version = get_kb_item("cisco/ip_phone/version"))
    exit(0);

  version = eregmatch(pattern: "sip88xx\.([0-9-]+)", string: version);
  if (version[1] && version[1] =~ "^11-0-1") {
    report = report_fixed_ver(installed_version: version[1], fixed_version: "11.7(1)MN367");
    security_message(port: 0, data: report);
  }
}

exit(0);
