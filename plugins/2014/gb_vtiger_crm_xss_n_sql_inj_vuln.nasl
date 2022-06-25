###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vtiger_crm_xss_n_sql_inj_vuln.nasl 32350 2014-01-03 11:00:19Z Jan$
#
# vTiger CRM Cross Site Scripting and SQL Injection Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.804055");
  script_version("2019-04-26T10:52:18+0000");
  script_cve_id("CVE-2013-5091");
  script_bugtraq_id(62487);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-04-26 10:52:18 +0000 (Fri, 26 Apr 2019)");
  script_tag(name:"creation_date", value:"2014-01-03 11:00:19 +0530 (Fri, 03 Jan 2014)");
  script_name("vTiger CRM Cross Site Scripting and SQL Injection Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_vtiger_crm_detect.nasl");
  script_mandatory_keys("vtiger/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://web.archive.org/web/20130808134443/https://www.vtiger.com/blogs/?p=1467");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Sep/78");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/28409");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23168");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/vtiger-540-cross-site-scripting");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/vtigercrm/files/vtiger%20CRM%205.4.0/Core%20Product/VtigerCRM540_Security_Patch.zip");

  script_tag(name:"summary", value:"This host is installed with vTiger CRM and is prone to xss and sql injection
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 6.0 or later. Alternatively apply the referenced security patch for 5.4.0.");

  script_tag(name:"insight", value:"Flaw is due to the /index.php script not properly sanitizing user-supplied
  input to the 'onlyforuser' parameter and savetemplate.php, deletetask.php, edittask.php, savetask.php and
  saveworkflow.php scripts are not properly sanitizing the input passed via the 'return_url' parameter.");

  script_tag(name:"affected", value:"vTiger CRM version 5.4.0 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML or
  script code and inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!vtVer = get_app_version(cpe:CPE, port:port))
  exit(0);

if (version_is_less_equal(version:vtVer, test_version:"5.4.0")) {
  report = report_fixed_ver(installed_version:vtVer, fixed_version:"6.0.0");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);