###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_prtg_netmon_xss_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# PRTG Network Monitor XSS Vulnerability
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

CPE = 'cpe:/a:paessler:prtg_network_monitor';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106246");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-15 09:47:18 +0700 (Thu, 15 Sep 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2016-5078");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PRTG Network Monitor XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_prtg_network_monitor_detect.nasl");
  script_mandatory_keys("prtg_network_monitor/installed");

  script_tag(name:"summary", value:"PRTG Network Monitor is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability allows a malicious actor to inject persistent JavaScript
and HTML code into various fields within PRTG's Network Monitor web management interface. When this data is
viewed within the web console the code will execute within the context of the authenticated user. This will
allow a malicious actor to conduct attacks which can be used to modify the system configuration, compromise data,
take control of the product or launch attacks against the authenticated user's host system.

The persistent XSS vulnerability is delivered via the network SNMP discovery process of a device. If the network
device that is discovered contains JavaScript or HTML code specified as the following SNMP OID objects, then
the code will be rendered within the context of the authenticated user who views the 'System Information' web
page of the discovered device.");

  script_tag(name:"impact", value:"A successful exploit could allow an attacker to execute arbitrary script
code in the context of the authenticated user.");

  script_tag(name:"affected", value:"PRTG Network Monitor before 16.2.24.4045");

  script_tag(name:"solution", value:"Update to 16.2.24.4045");

  script_xref(name:"URL", value:"https://community.rapid7.com/community/infosec/blog/2016/09/07/multiple-disclosures-for-multiple-network-management-systems-part-2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "16.2.24.4045")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.2.24.4045");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
