###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntp_entropy_sec_weakness_brute_force_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# NTP Insufficient Entropy Security Weakness Brute Force Attack Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809781");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2014-9293");
  script_bugtraq_id(71757);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-16 17:55:06 +0530 (Mon, 16 Jan 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("NTP Insufficient Entropy Security Weakness Brute Force Attack Vulnerability");

  script_tag(name:"summary", value:"The host is running NTP and is prone to
  brute force attack vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in 'config_auth'
  function in ntpd when an auth key is not configured, improperly generates a key
  and makes it easier for remote attackers to conduct brute force attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to defeat cryptographic protection mechanisms via a brute-force attack.");

  script_tag(name:"affected", value:"NTP versions before 4.2.7p11");

  script_tag(name:"solution", value:"Upgrade to NTP version 4.2.7p11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/852879");
  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=2665");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ntp_open.nasl");
  script_mandatory_keys("NTP/Running", "NTP/Linux/Ver");
  script_require_udp_ports(123);
  script_xref(name:"URL", value:"http://www.ntp.org");
  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if(!ntpPort = get_app_port(cpe:CPE)){
 exit(0);
}

if(!ntpVer = get_app_version(cpe:CPE, port:ntpPort)){
  exit(0);
}

if (revcomp(a: ntpVer, b: "4.2.7p11") < 0)
{
  report = report_fixed_ver(installed_version:ntpVer, fixed_version:"4.2.7p11");
  security_message(data:report, port:ntpPort, proto:"udp");
  exit(0);
}
