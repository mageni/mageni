###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_telepresence_server_cisco-sa-20170315-tps.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco TelePresence Server API Privilege Vulnerability
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

CPE = "cpe:/a:cisco:telepresence_server_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106664");
  script_cve_id("CVE-2017-3815");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 12106 $");

  script_name("Cisco TelePresence Server API Privilege Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170315-tps");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in Cisco TelePresence Server Software could allow an
unauthenticated, remote attacker to emulate Cisco TelePresence Server endpoints.");

  script_tag(name:"insight", value:"The vulnerability is due to how session identification information is
maintained by a specific API of the affected software. An attacker could exploit this vulnerability by snooping
temporary, unencrypted keys on an affected system.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to emulate a Cisco TelePresence
Server endpoint.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-16 14:46:37 +0700 (Thu, 16 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_telepresence_server_detect.nasl");
  script_mandatory_keys("cisco_telepresence_server/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("cisco_telepresence_server/model");
if (!model || model =~ '^7010$' || model =~ 'Media (3|8)(1|2)0' || model =~ "VM")
  exit(99);

if (!version = get_app_version(cpe:CPE))
  exit(0);

affected = make_list(
		'4.2(4.19)',
		'4.2(4.17)',
		'4.2(4.18)');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
