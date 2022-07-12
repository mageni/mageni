###############################################################################
# OpenVAS Vulnerability Test
#
# LDAP Account Manager XSS And CSRF Vulnerabilities Mar18
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ldap_account_manager:ldap_account_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812835");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-8763", "CVE-2018-8764");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-03-26 15:34:35 +0530 (Mon, 26 Mar 2018)");
  script_name("LDAP Account Manager XSS And CSRF Vulnerabilities Mar18");

  script_tag(name:"summary", value:"The host is installed with LDAP account
  manager and is prone to XSS and CSRF vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - LDAP account manager fails to sanitize the 'dn' parameter and
    the 'template' parameter of the cmd.php page.

  - LDAP account manager fails to sanitize 'sec_token' parameter of the
    'passwordchange' function in the ajax.php page which is revealed in URL.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to inject and execute JavaScript code in the application context and defeat a
  CSRF protection mechanism to reveal sensitive information via URL.");

  script_tag(name:"affected", value:"LDAP account manager version 6.2. Other
  versions may also be affected.");

  script_tag(name:"solution", value:"Upgrade to version 6.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Mar/45");
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_ldap_account_manager_detect.nasl");
  script_mandatory_keys("ldap_account_manager/installed");
  script_xref(name:"URL", value:"https://www.ldap-account-manager.org/lamcms");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!lport = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:lport, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(vers == "6.2")
{
 report = report_fixed_ver(installed_version:vers, fixed_version:"6.3" , install_path:path);
 security_message(port:lport, data:report);
 exit(0);
}

exit(0);
