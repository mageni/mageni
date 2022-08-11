###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_limesurvey_mult_vuln.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# LimeSurvey Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:limesurvey:limesurvey";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106064");
  script_version("$Revision: 12149 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-13 09:53:01 +0700 (Fri, 13 May 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/installed");

  script_tag(name:"summary", value:"LimeSurvey is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unauthenticated attackers can pass specially crafted data to the
entry points result in following vulnerabilities:

1. Unauthenticated local file disclosure
An attacker can craft a malicious PHP serialized string containing a list of arbitrary files. This list
can be sent to the Lime Survey backup feature for downloading without prior authentication. Any files
accessible with the privileges of the web server user can be downloaded.

2. Unauthenticated database dump
An attacker can request the database backup feature without authentication. The whole Lime Survey database
can be downloaded including username and hashed password of the administrator account.

3. Unauthenticated arbitrary remote code execution
An attacker can inject arbitrary PHP code into the application source code allowing to plant a malicious
web backdoor to access underlying web server.

4. Multiple reflective cross-site scripting
The application is prone to multiple reflective cross-site scripting vulnerabilities.");

  script_tag(name:"impact", value:"The impact ranges from unauthenticated file disclosure until remote code
execution.");

  script_tag(name:"affected", value:"LimeSurvey 2.05 to 2.06+ Build 151014");

  script_tag(name:"solution", value:"Update to LimeSurvey 2.06+ Build 151016 or later.");

  script_xref(name:"URL", value:"https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20151022-0_Lime_Survey_multiple_critical_vulnerabilities_v10.txt");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version != "unknown") {
  if ((revcomp(a: version, b: "2.06+_build_151014") < 0) &&
      (revcomp(a: version, b: "2.05_build_150413") >= 0)) {
    report = report_fixed_ver(installed_version:version, fixed_version: "2.06+_build_151014");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
