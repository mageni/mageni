###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_privilege_escalation_vuln.nasl 11923 2018-10-16 10:38:56Z mmartin $
#
# OTRS Framework Privilege Escalation Vulnerability (OSA-2017-10)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812273");
  script_version("$Revision: 11923 $");
  script_cve_id("CVE-2017-17476");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 12:38:56 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-26 13:32:26 +0530 (Tue, 26 Dec 2017)");
  ## Application is vulnerable only if system has cookie support disabled
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OTRS Framework Privilege Escalation Vulnerability (OSA-2017-10)");

  script_tag(name:"summary", value:"The host is installed with OTRS Framework
  and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as when an attacker sends a
  specially prepared email to an OTRS system while system has cookie support
  disabled, a logged in agent clicking a link in this email will leak the session
  information to external systems.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to hijack web sessions and consequently gain privileges via a
  crafted email.");

  script_tag(name:"affected", value:"Open Ticket Request System (OTRS) 4.0.x
  before 4.0.28, 5.0.x before 5.0.26, and 6.0.x before 6.0.3");

  script_tag(name:"solution", value:"Upgrade to 6.0.3 or 4.0.28 or 5.0.26
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2017-10-security-update-otrs-framework");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!otPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:otPort, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if((vers =~ "^(4\.0)") && (version_is_less(version:vers, test_version:'4.0.28'))){
  fix = '4.0.28';
}

else if((vers =~ "^(5\.0)") && (version_is_less(version:vers, test_version:'5.0.26'))){
  fix = '5.0.26';
}

else if((vers =~ "^(6\.0)") && (version_is_less(version:vers, test_version:'6.0.3'))){
  fix = '6.0.3';
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report, port:otPort);
  exit(0);
}
exit(0);
