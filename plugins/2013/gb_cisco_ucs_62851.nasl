###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ucs_62851.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Cisco Unified Computing System Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
CPE = "cpe:/a:cisco:unified_computing_system_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103805");
  script_bugtraq_id(59451, 59453, 59457, 59459, 59455);
  script_cve_id("CVE-2013-1182", "CVE-2013-1183", "CVE-2013-1184", "CVE-2013-1185", "CVE-2013-1186");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11865 $");

  script_name("Cisco Unified Computing System Multiple Vulnerabilities");


  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59451");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59453");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59457");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59459");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59455");

  script_xref(name:"URL", value:"http://www.cisco.com/");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-10 19:10:32 +0200 (Thu, 10 Oct 2013)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ucs_manager_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("cisco_ucs_manager/installed");

  script_tag(name:"impact", value:"CSCtc91207:
An attacker can exploit this issue to bypass the authentication mechanism
and impersonate other users of the system. This may lead to further
attacks.

CSCtd32371:
Attackers can exploit this issue to execute arbitrary code within the
context of the affected application. Failed exploit attempts will result in
denial-of-service conditions.

CSCtg48206:
Attackers can exploit this issue to cause the service to stop responding
resulting in denial-of-service conditions.

CSCtq86543:
Successful exploits will allow attackers to obtain sensitive information.
This may result in the complete compromise of the system.

CSCts53746:
An attacker can exploit this issue to bypass the authentication mechanism
and gain access to the IP KVM console of the physical or virtual device.
This may lead to further attacks.");
  script_tag(name:"vuldetect", value:"Check the Cisco Unified Computing System Version");
  script_tag(name:"insight", value:"This issue is being tracked by Cisco bug IDs:
CSCtc91207
CSCtd32371
CSCtg48206
CSCtq86543
CSCts53746");
  script_tag(name:"solution", value:"Update to 2.1.1e");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Cisco Unified Computing System is prone to multiple
vulnerabilities");
  script_tag(name:"affected", value:"Cisco Unified Computing System 1.0(x)
1.1(x)
1.2(x)
1.3(x)
1.4(x)
2.0(1x) and Prior");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

version = get_app_version(cpe:CPE, nofork:TRUE);
if(!version)exit(0);

vers = eregmatch(pattern:"^([0-9.]+)\(([^)]+)\)", string:version);
if(isnull(vers[1]) || isnull(vers[2]))exit(0);

major = vers[1];
build = vers[2];

vuln = FALSE;

# cisco recommended to update to 2.1.1e. So we check for < 2.1.1e. Example
# Version: 2.0(1s)
if(version_is_less(version:major, test_version:"2.1")) vuln = TRUE;
if(version_is_equal(version:major, test_version:"2.1")) {
  if(build =~ "^(0[^0-9]|1[a-d])") vuln = TRUE;
}

if(vuln) {
  report = report_fixed_ver( installed_version:version, fixed_version:'2.1.1e' );
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
