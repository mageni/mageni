###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_aironet_cisco-sa-20170405-cme.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Mobility Express 2800 and 3800 Series Wireless LAN Controllers Shell Bypass Vulnerability
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
# of the License, or (at your option) any later version.
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

CPE = "cpe:/o:cisco:wireless_lan_controller_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106721");
  script_cve_id("CVE-2016-9197");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco Mobility Express 2800 and 3800 Series Wireless LAN Controllers Shell Bypass Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-cme");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See vendor advisory.");

  script_tag(name:"summary", value:"A vulnerability in the CLI command parser of the Cisco Mobility Express 2800
and 3800 Series Wireless LAN Controllers could allow an authenticated, local attacker to obtain access to the
underlying operating system shell with root-level privileges.");

  script_tag(name:"insight", value:"The vulnerability is due to incorrect permissions being assigned to
configured users on the device. An attacker could exploit this vulnerability by authenticating to the device and
issuing certain commands at the CLI.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to access the underlying
operating system shell with root access.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-07 10:27:08 +0200 (Fri, 07 Apr 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_wlc_version.nasl");
  script_mandatory_keys("cisco_wlc/version", "cisco_wlc/model");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("cisco_wlc/model");
if (!model || model !~ "^AIR-AP(2|3)8[0-9]{2}")
  exit(0);

if (!version = get_app_version(cpe:CPE))
  exit(0);

if (version == "8.3.102.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

