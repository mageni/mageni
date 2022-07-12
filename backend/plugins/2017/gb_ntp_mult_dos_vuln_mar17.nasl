###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntp_mult_dos_vuln_mar17.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# NTP Multiple Denial-of-Service Vulnerabilities -Mar17
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
  script_oid("1.3.6.1.4.1.25623.1.0.810678");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2017-6464", "CVE-2017-6462", "CVE-2017-6463", "CVE-2017-6455",
                "CVE-2017-6452", "CVE-2017-6459", "CVE-2017-6458", "CVE-2017-6451",
                "CVE-2017-6460", "CVE-2016-9042");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-23 11:35:22 +0530 (Thu, 23 Mar 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("NTP Multiple Denial-of-Service Vulnerabilities -Mar17");

  script_tag(name:"summary", value:"The host is running NTP and is prone to
  multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to

  - Improper handling of a malformed mode configuration directive.

  - A buffer overflow error in Legacy Datum Programmable Time Server refclock
    driver.

  - Improper handling of an invalid setting via the :config directive.

  - Incorrect pointer usage in the function 'ntpq_stripquotes'.

  - No allocation of memory for a specific amount of items of the same size in
    'oreallocarray' function.

  - ntpd configured to use the PPSAPI under Windows.

  - Limited passed application path size under Windows.

  - An error leading to garbage registry creation in Windows.

  - Copious amounts of Unused Code.

  - Off-by-one error in Oncore GPS Receiver.

  - Potential Overflows in 'ctl_put' functions.

  - Improper use of 'snprintf' function in mx4200_send function.

  - Buffer Overflow in ntpq when fetching reslist from a malicious ntpd.

  - Potential Overflows in 'ctl_put' functions.

  - Potential denial of service in origin timestamp check functionality of ntpd.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to conduct denial of service condition.");

  script_tag(name:"affected", value:"NTP versions 4.x before 4.2.8p10 and 4.3.x
  before 4.3.94");

  script_tag(name:"solution", value:"Upgrade to NTP version 4.2.8p10 or 4.3.94
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3389");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3388");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3387");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3386");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3385");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3384");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3383");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3382");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3381");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3380");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3379");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3378");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3377");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3376");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3361");
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

if(ntpVer =~ "^(4\.(0|1|2))")
{
  if(revcomp(a: ntpVer, b: "4.2.8p10") < 0)
  {
    report = report_fixed_ver(installed_version:ntpVer, fixed_version:"4.2.8p10");
    security_message(data:report, port:ntpPort, proto:"udp");
    exit(0);
  }
}

else if(ntpVer =~ "^(4\.3)")
{
  if((revcomp(a: ntpVer, b: "4.3.94") < 0))
  {
    report = report_fixed_ver(installed_version:ntpVer, fixed_version:"4.3.94");
    security_message(data:report, port:ntpPort, proto:"udp");
    exit(0);
  }
}
