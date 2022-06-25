###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_apic_em_unauth_access_vuln.nasl 12047 2018-10-24 07:38:41Z cfischer $
#
# Cisco APIC Enterprise Module Unauthorized Access Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:cisco:application_policy_infrastructure_controller_enterprise_module";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807836");
  script_version("$Revision: 12047 $");
  script_cve_id("CVE-2016-1386");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 09:38:41 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-13 15:58:36 +0530 (Mon, 13 Jun 2016)");
  script_name("Cisco APIC Enterprise Module Unauthorized Access Vulnerability");

  script_tag(name:"summary", value:"This host is running Cisco APIC Enterprise Module
  and is prone to unauthorized access vulnerability.");

  script_tag(name:"vuldetect", value:"Check for the vulnerable version of Cisco
  APIC Enterprise Module.");

  script_tag(name:"insight", value:"The error exist due to insufficient protection
  of API functions, which does not handle modified attribute-value pairs.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to create false system notifications for administrators and trick the
  administrative users into performing a malicious task on behalf of the attacker.");

  script_tag(name:"affected", value:"Cisco APIC-EM version 1.0(1) is affected.");

  script_tag(name:"solution", value:"Apply the updates from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # advisory is very vague about effected versions

  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux15521");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160428-apic");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_dependencies("gb_cisco_apic_em_web_detect.nasl");
  script_mandatory_keys("cisco/apic_em/version");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!cisPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(cisVer = get_app_version(cpe:CPE, port:cisPort))
{
  if(cisVer =~ "^1\.0\(1\)")
  {
    report = report_fixed_ver(installed_version:cisVer, fixed_version:'See vendor advisory');
    security_message(port:cisPort, data:report);
    exit(0);
  }
}

exit(99);
