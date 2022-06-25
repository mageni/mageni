###############################################################################
# OpenVAS Vulnerability Test
#
# NTP 'ctl_getitem()' And 'decodearr()' Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812790");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-7182", "CVE-2018-7183");
  script_bugtraq_id(103191, 103351);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-03-07 11:25:49 +0530 (Wed, 07 Mar 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("NTP 'ctl_getitem()' And 'decodearr()' Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is running NTP and is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to

  - An error in 'ctl_getitem()' which is used by ntpd to process incoming mode
    6 packets. A malicious mode 6 packet can be sent to an ntpd instance,
    will cause 'ctl_getitem()' to read past the end of its buffer.

  - An error in 'decodearr()' which is used by ntpq can write beyond its buffer
    limit.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and obtain sensitive information that may lead to
  further attacks.");

  script_tag(name:"affected", value:"NTP versions 4.2.8p6 before 4.2.8p11");

  script_tag(name:"solution", value:"Upgrade to NTP version 4.2.8p11
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3412");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3414");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/SecurityNotice#February_2018_ntp_4_2_8p11_NTP_S");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ntp_open.nasl");
  script_mandatory_keys("NTP/Running", "NTP/Linux/Ver");
  script_require_udp_ports(123);
  script_xref(name:"URL", value:"http://www.ntp.org/downloads.html");
  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if(!ntpPort = get_app_port(cpe:CPE)){
 exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:ntpPort, exit_no_version:TRUE)) exit(0);
ntpVer = infos['version'];
path = infos['location'];

if(ntpVer =~ "^(4\.2\.8)")
{
  if(revcomp(a: ntpVer, b: "4.2.8p6") >= 0 && revcomp(a: ntpVer, b: "4.2.8p11") < 0)
  {
    report = report_fixed_ver(installed_version:ntpVer, fixed_version:"4.2.8p11", install_path:path);
    security_message(data:report, port:ntpPort, proto:"udp");
    exit(0);
  }
}
exit(99);
