###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vtiger_crm_mult_xss_vuln_apr14.nasl 12926 2019-01-03 03:38:48Z ckuersteiner $
#
# Vtiger 'return_url' Parameter Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:vtiger:vtiger_crm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804541");
  script_version("$Revision: 12926 $");
  script_cve_id("CVE-2013-7326");
  script_bugtraq_id(64236);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-03 04:38:48 +0100 (Thu, 03 Jan 2019) $");
  script_tag(name:"creation_date", value:"2014-04-17 17:45:25 +0530 (Thu, 17 Apr 2014)");

  script_name("Vtiger 'return_url' Parameter Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Vtiger CRM and is prone to multiple XSS
vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws are due to improper sanitation of user supplied input passed via
'return_url' parameter to savetemplate.php and unspecified vectors to deletetask.php, edittask.php, savetask.php,
or saveworkflow.php.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Vtiger CRM version 5.4.0");

  script_tag(name:"solution", value:"Upgrade to the latest version of Vtiger 6.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/89662");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Dec/51");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124402");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vtiger_crm_detect.nasl");
  script_mandatory_keys("vtiger/detected");
  script_require_ports("Services/www", 80, 8888);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!http_port = get_app_port(cpe:CPE))
  exit(0);

if(!vtVer = get_app_version(cpe:CPE, port:http_port))
  exit(0);

if(version_is_equal(version:vtVer, test_version:"5.4.0")) {
  report = report_fixed_ver(installed_version: vtVer, fixed_version: "6.0.0");
  security_message(port:http_port, data: report);
  exit(0);
}

exit(99);
