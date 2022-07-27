###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_webex_cisco-sa-20170118-wms.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco WebEx Meetings Server Cross-Site Request Forgery Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106529");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-19 11:43:50 +0700 (Thu, 19 Jan 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-3794");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco WebEx Meetings Server Cross-Site Request Forgery Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_webex_meetings_server_detect.nasl");
  script_mandatory_keys("cisco/webex/detected");

  script_tag(name:"summary", value:"A vulnerability in Cisco WebEx Meetings Server could allow an
unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack against an administrative
user.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient CSRF protections. An attacker
could exploit this vulnerability by convincing the user of the affected system to follow a malicious link or
visit an attacker-controlled website.");

  script_tag(name:"impact", value:"A successful exploit could allow an attacker to submit arbitrary requests to
the affected device via the Administration pages with the privileges of the user.");

  script_tag(name:"affected", value:"Cisco WebEx Meetings Server version 2.6");

  script_tag(name:"solution", value:"See the vendors advisory for solutions.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170118-wms");

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
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
