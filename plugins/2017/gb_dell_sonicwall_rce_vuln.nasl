###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_sonicwall_rce_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Dell SonicWALL Secure Remote Access (SRA) Multiple Remote Command Execution Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/o:dell:sonicwall_secure_remote_access_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106980");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-24 13:41:24 +0700 (Mon, 24 Jul 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-9682", "CVE-2016-9683", "CVE-2016-9684");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dell SonicWALL Secure Remote Access (SRA) Multiple Remote Command Execution Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dell_sonicwall_sma_detection.nasl");
  script_mandatory_keys("sonicwall/sra/detected");

  script_tag(name:"summary", value:"SonicWall Secure Remote Access is prone to multiple remote command execution
vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SonicWall Secure Remote Access is prone to multiple remote command execution
vulnerabilities:

  - The vulnerability exist in a section of the machine's administrative interface for performing configurations
related to on-connect scripts to be launched for users's connecting.

  - Two Remote Command Injection vulnerabilities in its web administrative interface. These vulnerabilities occur
in the diagnostics CGI (/cgi-bin/diagnostics) component responsible for emailing out information about the state
of the system. (CVE-2016-9682)

  - Remote Command Injection vulnerability in its web administrative interface. This vulnerability occurs in the
'extensionsettings' CGI (/cgi-bin/extensionsettings) component responsible for handling some of the server's
internal configurations. (CVE-2016-9683)

  - Remote Command Injection vulnerability in its web administrative interface. This vulnerability occurs in the
'viewcert' CGI (/cgi-bin/viewcert) component responsible for processing SSL certificate information.
(CVE-2016-9684)");

  script_tag(name:"impact", value:"An attacker may execute arbitrary code.");

  script_tag(name:"affected", value:"Dell SonicWALL SRA versions 8.1.0.2-14sv and prior.");

  script_tag(name:"solution", value:"Upgrade to version 8.1.0.6-21sv or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42343/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

check_vers = ereg_replace(string: version, pattern: "-", replace: ".");

if (version_is_less(version: check_vers, test_version: "8.1.0.6.21sv")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.0.6-21sv");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
