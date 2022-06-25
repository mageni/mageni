###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntp_remote_dos_vuln_nov16.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# NTP.org 'ntp' 'decodenetnum' And 'loop counter underrun' DoS Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810221");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2015-7855", "CVE-2015-7848");
  script_bugtraq_id(77283, 77275);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-29 12:32:57 +0530 (Tue, 29 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("NTP.org 'ntp' 'decodenetnum' And 'loop counter underrun' DoS Vulnerabilities");
  script_tag(name:"summary", value:"The host is running NTP.org's reference
  implementation of NTP server, ntpd and is prone to multiple denial of service
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors are due to

  - A flaw in 'decodenetnum' function which will abort with an assertion failure
    instead of simply returning a failure condition when ntpd is fed a crafted
    packet.

  - An integer overflow can occur in application.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"All ntp-4 release prior to 4.2.8p4 and 4.3.0
  prior to 4.3.77");
  script_tag(name:"solution", value:"Upgrade to ntp4.2.8p4 or 4.3.77 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40840");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug2913");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("ntp_open.nasl");
  script_mandatory_keys("NTP/Running", "NTP/Linux/Ver");
  script_require_udp_ports(123);
  script_xref(name:"URL", value:"http://www.ntp.org");
  exit(0);
}


include("version_func.inc");
include("revisions-lib.inc");

##Port
ntpPort = 123;

if("ntpd" >!< get_kb_item("NTP/Linux/FullVer")){
  exit(0);
}

if(!ntpVer = get_kb_item("NTP/Linux/Ver")){
  exit(0);
}

if(ntpVer =~ "^(4\.(0|1|2))")
{
  if (revcomp(a: ntpVer, b: "4.2.8p4") < 0)
  {
    VULN = TRUE;
    fix = "4.2.8p4";
  }
}

else if(ntpVer =~ "^(4\.3)")
{
  if (revcomp(a: ntpVer, b: "4.3.77") < 0)
  {
    VULN = TRUE;
    fix = "4.3.77";
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:ntpVer, fixed_version:fix);
  security_message(data:report, port:ntpPort, proto:"udp");
  exit(0);
}
