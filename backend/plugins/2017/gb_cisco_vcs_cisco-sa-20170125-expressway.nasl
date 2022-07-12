###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_vcs_cisco-sa-20170125-expressway.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco TelePresence VCS Denial of Service Vulnerability
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

CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106544");
  script_cve_id("CVE-2017-3790");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco TelePresence VCS Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170125-expressway");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version X8.8.2 or higher.");

  script_tag(name:"summary", value:"A vulnerability in the received packet parser of Cisco TelePresence Video
Communication Server (VCS) software could allow an unauthenticated, remote attacker to cause a reload of the
affected system, resulting in a denial of service (DoS) condition.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient size validation of user-supplied
data. An attacker could exploit this vulnerability by sending crafted H.224 data in Real-Time Transport Protocol
(RTP) packets in an H.323 call.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to overflow a buffer in a cache that
belongs to the received packet parser, which will result in a crash of the application, resulting in a DoS
condition.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-26 11:29:25 +0700 (Thu, 26 Jan 2017)");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_vcs_detect.nasl", "gb_cisco_vcs_ssh_detect.nasl");
  script_mandatory_keys("cisco_vcs/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "8.8.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "X8.8.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
