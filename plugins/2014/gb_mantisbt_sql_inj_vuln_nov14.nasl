###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantisbt_sql_inj_vuln_nov14.nasl 12818 2018-12-18 09:55:03Z ckuersteiner $
#
# MantisBT SQL Injection Vulnerability -01 November14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804891");
  script_version("$Revision: 12818 $");
  script_cve_id("CVE-2014-8554", "CVE-2014-9281", "CVE-2014-9280", "CVE-2014-9117",
                "CVE-2014-6387", "CVE-2014-9506", "CVE-2014-9089", "CVE-2014-6316",
                "CVE-2014-9388", "CVE-2014-8553");
  script_bugtraq_id(70856, 71371, 71361, 71321, 69780, 71298, 71478, 71553);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2014-11-25 14:59:21 +0530 (Tue, 25 Nov 2014)");

  script_name("MantisBT SQL Injection Vulnerability -01 November14");

  script_tag(name:"summary", value:"This host is installed with MantisBT and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - an error in the 'mc_project_get_attachments' function in
  api/soap/mc_project_api.php script which does not properly sanitize
  user-supplied input before using it in SQL queries.

  - the view_all_bug_page.php script not properly sanitizing user-supplied
  input to the 'sort' and 'dir' parameters to view_all_set.php.

  - null byte poisoning in LDAP authentication.

  - the copy_field.php script which does not validate input to the 'dest_id'
  parameter before returning it to users.

  - input passed via the 'filter' parameter is not properly sanitized by the
  'current_user_get_bug_filter' function in the core/current_user_api.php script.

  - an error in the CAPTCHA system that is triggered upon registration.

  - an error in user rights to see a given ticket and its related issues.

  - application does not validate the 'return' parameter upon submission to
  the /bugs/login_page.php script.

  - input passed via the 'handler_id' parameter is not properly sanitized when
  passed via the bug_report.php script.

  - an error in the 'mci_account_get_array_by_id' function in the
  api/soap/mc_account_api.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to inject or manipulate SQL queries in the backend database, execute arbitrary
  script code in a user's browser session within the trust relationship between
  their browser and the server, execute arbitrary PHP code, bypass security
  mechanisms, conduct open redirect and phishing attacks, assign arbitrary issues,
  and obtain sensitive information.");

  script_tag(name:"affected", value:"MantisBT version 1.2.17 and earlier");

  script_tag(name:"solution", value:"Upgrade to MantisBT version 1.2.18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/98457");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q4/479");
  script_xref(name:"URL", value:"http://www.mantisbt.org/bugs/view.php?id=17812");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mantis_detect.nasl");
  script_mandatory_keys("mantisbt/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!manPort = get_app_port(cpe:CPE))
  exit(0);

if(!manVer = get_app_version(cpe:CPE, port:manPort))
  exit(0);

if(version_is_less(version:manVer, test_version:"1.2.18")) {
  report = report_fixed_ver(installed_version: manVer, fixed_version: "1.2.18");
  security_message(port:manPort, data: report);
  exit(0);
}

exit(99);
