###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_spa_cisco-sa-20160831-spa.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Cisco Small Business SPA3x/5x Series Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106217");
  script_version("$Revision: 12149 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-01 13:50:07 +0700 (Thu, 01 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2016-1469");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Small Business SPA3x/5x Series Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_spa_voip_device_detect.nasl");
  script_mandatory_keys("cisco/spa_voip/model", "cisco/spa_voip/version");

  script_tag(name:"summary", value:"A vulnerability in the HTTP framework of Cisco Small Business SPA300 Series
IP Phones, Cisco Small Business SPA500 Series IP Phones, and Cisco SPA51x IP Phones could allow an
unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device.");

  script_tag(name:"insight", value:"The vulnerability is due to incorrect handling of malformed HTTP traffic.
An attacker could exploit this vulnerability by sending crafted HTTP requests to an affected device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to deny service continually by sending
crafted HTTP requests to a phone, resulting in a DoS condition.");

  script_tag(name:"affected", value:"SPA300 Series IP Phones, SPA500 Series IP Phones and SPA51x IP Phones.");

  script_tag(name:"solution", value:"Cisco has released software updates that address this vulnerability.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160831-spa");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!model = get_kb_item("cisco/spa_voip/model"))
  exit(0);

if (model !~ "^SPA(30|50|51).")
  exit(0);

if (!version = get_kb_item("cisco/spa_voip/version"))
  exit(0);

if (version_is_less_equal(version: version, test_version: "7.5.7.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.6.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
