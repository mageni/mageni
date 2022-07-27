###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntp_mult_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# NTP Multiple Vulnerabilities
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809858");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2014-9751", "CVE-2014-9750");
  script_bugtraq_id(72584, 72583);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-05 12:03:35 +0530 (Thu, 05 Jan 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("NTP Multiple Vulnerabilities");
  script_tag(name:"summary", value:"The host is running NTP and is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to

  - The 'read_network_packet' function in 'ntp_io.c' in ntpd does not properly
    determine whether a source IP address is an IPv6 loopback address.

  - An error in 'ntp_crypto.c' script in ntpd when Autokey Authentication is
    enabled.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to obtain sensitive information from process memory or cause a denial
  of service, to conduct spoofing attack and this can lead to further attacks.");

  script_tag(name:"affected", value:"NTP versions 4.x before 4.2.8p1");

  script_tag(name:"solution", value:"Upgrade to NTP version 4.2.8p1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=2672");
  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=2671");
  script_xref(name:"URL", value:"https://github.com/ntp-project/ntp/blob/stable/ChangeLog");
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

# #Grep for vulnerable version
if(ntpVer =~ "^(4\.(0|1|2))")
{
  if (revcomp(a: ntpVer, b: "4.2.8p1") < 0)
  {
    report = report_fixed_ver(installed_version:ntpVer, fixed_version:"4.2.8p1");
    security_message(data:report, port:ntpPort, proto:"udp");
    exit(0);
  }
}
