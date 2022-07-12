###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_virusscan_enterprise_lin_mult_vuln.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# McAfee VirusScan Enterprise for Linux Multiple Vulnerabilities
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

CPE = 'cpe:/a:mcafee:virusscan_enterprise_for_linux';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106470");
  script_version("$Revision: 12149 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-14 11:28:02 +0700 (Wed, 14 Dec 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-8016", "CVE-2016-8017", "CVE-2016-8018", "CVE-2016-8019", "CVE-2016-8020",
"CVE-2016-8021", "CVE-2016-8022", "CVE-2016-8023", "CVE-2016-8024", "CVE-2016-8025");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("McAfee VirusScan Enterprise for Linux Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mcafee_virusscan_enterprise_detect_lin.nasl");
  script_mandatory_keys("mcafee/virusscan_enterprise_linux/installed");

  script_tag(name:"summary", value:"McAfee VirusScan Enterprise for Linux is prone to multiple
vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"McAfee VirusScan Enterprise for Linux is prone to multiple vulnerabilities:

  - Remote Unauthenticated File Existence Test (CVE-2016-8016)

  - Remote Unauthenticated File Read (CVE-2016-8017)

  - No Cross-Site Request Forgery Tokens (CVE-2016-8018)

  - Cross Site Scripting (CVE-2016-8019)

  - Authenticated Remote Code Execution and Privilege Escalation (CVE-2016-8020)

  - Web Interface Allows Arbitrary File Write to Known Location (CVE-2016-8021)

  - Remote Use of Authentication Tokens (CVE-2016-8022)

  - Brute Force Authentication Tokens (CVE-2016-8023)

  - Brute Force Authentication Tokens (CVE-2016-8024)

  - Authenticated SQL Injection (CVE-2016-8025)");

  script_tag(name:"impact", value:"An unauthenticated attacker may execute code when chained the vulnerabilities
together.");

  script_tag(name:"affected", value:"Version 2.0.3");

  script_tag(name:"solution", value:"Upgrade to Endpoint Security for Linux (ENSL) 10.2 or later.");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10181");
  script_xref(name:"URL", value:"https://nation.state.actor/mcafee.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Endpoint Security for Linux 10.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
