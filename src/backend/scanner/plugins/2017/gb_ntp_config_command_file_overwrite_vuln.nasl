###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntp_config_command_file_overwrite_vuln.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# NTP ':config' Command Arbitrary File Overwrite Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.811253");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2015-7703");
  script_bugtraq_id(77278);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-25 11:30:12 +0530 (Tue, 25 Jul 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("NTP ':config' Command Arbitrary File Overwrite Vulnerability");

  script_tag(name:"summary", value:"The host is running NTP and is prone to
  arbitrary file-overwrite vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper access
  restrictions for the 'pidfile' or 'driftfile' directives in NTP.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to send remote configuration requests, and if the attacker knows
  the remote configuration password, it's possible for an attacker to use
  the 'pidfile' or 'driftfile' directives to potentially overwrite other
  files.");

  script_tag(name:"affected", value:"All ntp-4 releases prior to 4.2.8p4 and
  4.3.0 prior to 4.3.77");

  script_tag(name:"solution", value:"Upgrade to NTP version 4.2.8p4 or 4.3.77
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug2902");
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
  if(revcomp(a: ntpVer, b: "4.2.8p4") < 0){
    fix = "4.2.8p4";
  }
}

else if(ntpVer =~ "^(4\.3)")
{
  if((revcomp(a: ntpVer, b: "4.3.77") < 0)){
    fix = "4.3.77";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:ntpVer, fixed_version:fix);
  security_message(data:report, port:ntpPort, proto:"udp");
  exit(0);
}
exit(0);
