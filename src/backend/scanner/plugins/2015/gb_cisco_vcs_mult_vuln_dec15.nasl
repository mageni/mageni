###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_vcs_mult_vuln_dec15.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Cisco TelePresence VCS and VCS Expressway Multiple Vulnerabilities Dec15
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806650");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-2015-6414", "CVE-2015-6413");
  script_bugtraq_id(79088, 79065);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-12-17 20:00:22 +0530 (Thu, 17 Dec 2015)");
  script_name("Cisco TelePresence VCS and VCS Expressway Multiple Vulnerabilities Dec15");

  script_tag(name:"summary", value:"This host is running Cisco TelePresence
  Video Communication Server and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - The use of the same encryption key across different customer.

  - The missing authorization checks on certain administrative pages.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to read and disclose certain sensitive data, and upload TLP files changing
  contents of VCS.");

  script_tag(name:"affected", value:"Cisco TelePresence Video Communication Server (VCS) version X8.6
  Cisco TelePresence Video Communication Server (VCS) Expressway version X8.6");

  script_tag(name:"solution", value:"Apply updates from Vendor. See the references for more details.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151209-tvc");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151210-tvcs");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_vcs_detect.nasl", "gb_cisco_vcs_ssh_detect.nasl");
  script_mandatory_keys("cisco_vcs/installed");
  exit(0);
}

include("host_details.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE)){
  exit(0);
}

if(version =~ "^8\.6($|[^0-9])")
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     Apply updates from Vendor\n';
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
