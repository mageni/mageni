###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_wlc_cisco-sa-20160831-wlc-1.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Cisco Wireless LAN Controller TSM SNMP Denial of Service Vulnerability
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

CPE = 'cpe:/o:cisco:wireless_lan_controller_software';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106218");
  script_version("$Revision: 12149 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-01 14:58:40 +0700 (Thu, 01 Sep 2016)");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2016-6375");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Wireless LAN Controller TSM SNMP Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_wlc_version.nasl");
  script_mandatory_keys("cisco_wlc/version");

  script_tag(name:"summary", value:"A vulnerability in the traffic stream metrics (TSM) implemented with the
Inter-Access Point Protocol (IAPP) of the Cisco Wireless LAN Controller (WLC) could allow an unauthenticated,
adjacent attacker to cause a denial of service (DoS) condition because the process on the WLC unexpectedly
restarts.");

  script_tag(name:"insight", value:"The occurs when an SNMP request for TSM information is received. An
attacker could exploit this vulnerability by sending crafted IAPP packets followed by an SNMP request for
TSM information to the targeted device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause a DoS condition when the
WLC unexpectedly restarts.");

  script_tag(name:"affected", value:"All versions of Cisco Wireless LAN Controller prior to the first fixed
versions of 8.0.140, 8.2.121.0, and 8.3.102.0.");

  script_tag(name:"solution", value:"Cisco has released software updates that address this vulnerability.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160831-wlc-1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_is_less(version: version, test_version: "8.0.140")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.140");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "8\.(1|2)") {
  if (version_is_less(version: version, test_version: "8.2.121.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.2.121.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "8\.3") {
  if (version_is_less(version: version, test_version: "8.3.102.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.3.102.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
