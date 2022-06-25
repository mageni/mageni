###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mybb_mult_vuln.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# MyBB Multiple Vulnerabilities
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

CPE = "cpe:/a:mybb:mybb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106276");
  script_version("$Revision: 12431 $");
  script_cve_id("CVE-2016-9402", "CVE-2016-9403", "CVE-2016-9404", "CVE-2016-9405", "CVE-2016-9406",
                "CVE-2016-9407", "CVE-2016-9408", "CVE-2016-9409", "CVE-2016-9410", "CVE-2016-9411",
                "CVE-2016-9412", "CVE-2016-9413", "CVE-2016-9414");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-22 09:06:56 +0700 (Thu, 22 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MyBB Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_mandatory_keys("MyBB/installed");

  script_tag(name:"summary", value:"MyBB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MyBB is prone to multiple vulnerabilities:

  - Possible SQL Injection in moderation tool

  - Missing permission check in newreply.php

  - Possible XSS Injection on login

  - Possible XSS Injection in member validation

  - Possible XSS Injection in User CP

  - Possible XSS Injection in Mod CP logs

  - Possible XSS Injection when editing users in Mod CP

  - Possible XSS Injection when pruning logs in ACP

  - Possibility of retrieving database details through templates

  - Disclosure of ACP path when sending mails from ACP

  - Low adminsid & sid entropy

  - Clickjacking in ACP

  - Missing directory listing protection in upload directories");

  script_tag(name:"impact", value:"The impact range from an authenticated attacker may be able to inject
SQL commands or execute an arbitrary script on the user's web browser.");

  script_tag(name:"affected", value:"myBB 1.8.6 and prior.");

  script_tag(name:"solution", value:"Update to myBB 1.8.7.");

  script_xref(name:"URL", value:"https://blog.mybb.com/2016/03/11/mybb-1-8-7-merge-system-1-8-7-release/");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138745/mybb186-validate.txt");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138744/mybb186-sql.txt");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Sep/40");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.8.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
