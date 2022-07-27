###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntp_multiple_vuln_jan17.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# NTP Multiple Vulnerabilities - Jan 2017
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
  script_oid("1.3.6.1.4.1.25623.1.0.809779");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2014-9296", "CVE-2014-9295");
  script_bugtraq_id(71758, 71761);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-01-16 17:05:06 +0530 (Mon, 16 Jan 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("NTP Multiple Vulnerabilities - Jan 2017");

  script_tag(name:"summary", value:"The host is running NTP and is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to

  - An error in the 'receive' function in ntp_proto.c script within application
    which continues to execute even after detecting a certain authentication error.

  - Multiple erros in ntpd functions 'crypto_recv' (when using autokey
    authentication), 'ctl_putdata', and 'configure'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code and other unspecified effect on the affected
  system.");

  script_tag(name:"affected", value:"NTP versions before 4.2.8");

  script_tag(name:"solution", value:"Upgrade to NTP version 4.2.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/852879");
  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=2668");
  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=2667");
  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=2669");
  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=2670");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ntp_open.nasl");
  script_mandatory_keys("NTP/Running", "NTP/Linux/Ver");
  script_require_udp_ports(123);

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ntpPort = get_app_port(cpe:CPE)){
 exit(0);
}

if(!ntpVer = get_app_version(cpe:CPE, port:ntpPort)){
  exit(0);
}

if(version_is_less(version:ntpVer, test_version:"4.2.8"))
{
  report = report_fixed_ver(installed_version:ntpVer, fixed_version:"4.2.8");
  security_message(data:report, port:ntpPort, proto:"udp");
  exit(0);
}
