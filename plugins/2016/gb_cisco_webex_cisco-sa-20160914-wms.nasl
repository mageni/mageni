###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_webex_cisco-sa-20160914-wms.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Cisco WebEx Meetings Server Denial of Service Vulnerability
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

CPE = 'cpe:/a:cisco:webex_meetings_server';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106253");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-16 12:38:55 +0700 (Fri, 16 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2016-1483");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco WebEx Meetings Server Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_webex_meetings_server_detect.nasl");
  script_mandatory_keys("cisco/webex/detected");

  script_tag(name:"summary", value:"A vulnerability in Cisco WebEx Meetings Server could allow an
unauthenticated, remote attacker to cause a denial of service (DoS) condition on a targeted system.");

  script_tag(name:"insight", value:"The vulnerability is due to improper validation of user accounts by
specific services. An unauthenticated, remote attacker could exploit this vulnerability by repeatedly attempting
to access a specific service, causing the system to perform computationally intensive tasks and resulting in a
DoS condition.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to cause a denial of service
condition.");

  script_tag(name:"affected", value:"Cisco WebEx Meetings Server version 2.6");

  script_tag(name:"solution", value:"Update to Cisco WebEx Meetings Server version 2.7 or later");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160914-wms");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version == "2.6") {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
