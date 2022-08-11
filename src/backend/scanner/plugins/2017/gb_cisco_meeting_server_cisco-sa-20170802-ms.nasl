###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_meeting_server_cisco-sa-20170802-ms.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Meeting Server H.264 Protocol Denial of Service Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:cisco:meeting_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140274");
  script_cve_id("CVE-2017-6763");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 12106 $");

  script_name("Cisco Meeting Server H.264 Protocol Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170802-ms");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the implementation of the H.264 protocol in Cisco Meeting
Server (CMS) could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an
affected system.");

  script_tag(name:"insight", value:"The vulnerability exists because the affected application does not properly
validate Fragmentation Unit (FU-A) protocol packets. An attacker could exploit this vulnerability by sending a
crafted H.264 FU-A packet through the affected application.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to cause a DoS condition on the
affected system due to an unexpected restart of the CMS media process on the system. Although the CMS platform
continues to operate and only the single, affected CMS media process is restarted, a brief interruption of media
traffic for certain users could occur.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-03 10:44:03 +0700 (Thu, 03 Aug 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_meeting_server_snmp_detect.nasl");
  script_mandatory_keys("cisco/meeting_server/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_in_range(version: version, test_version: "2.1.0", test_version2: "2.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

