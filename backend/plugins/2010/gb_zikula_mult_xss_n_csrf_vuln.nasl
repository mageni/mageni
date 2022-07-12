##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zikula_mult_xss_n_csrf_vuln.nasl 14168 2019-03-14 08:10:09Z cfischer $
#
# Zikula Multiple XSS and CSRF Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2011-02-16
#      - Added CVE CVE-2010-4729 and updated description
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:zikula:zikula_application_framework";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800773");
  script_version("$Revision: 14168 $");
  script_cve_id("CVE-2010-1732", "CVE-2010-1724", "CVE-2010-4729");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 09:10:09 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Zikula Multiple XSS and CSRF Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_zikula_detect.nasl");
  script_mandatory_keys("zikula/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39614");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58224");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/510988/100/0/threaded");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/xss_vulnerability_in_zikula_application_framework.html");

  script_tag(name:"insight", value:"- Input passed to the 'lang' parameter and to the 'func' parameter in the
  'index.php' is not properly sanitised before being returned to the user.

  - Failure in the 'users' module to properly verify the source of HTTP request.

  - Error in 'authid protection' mechanism for lostpassword form and mailpasswd
  processing, which makes it easier for remote attackers to generate a flood of password requests.");

  script_tag(name:"solution", value:"Upgrade to the Zikula version 1.2.3 or later.");

  script_tag(name:"summary", value:"This host is running Zikula and is prone to multiple cross-site
  scripting and cross-site request forgery vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to compromise the
  application, disclosure or modification of sensitive data, execute arbitrary
  HTML and script and conduct cross-site request forgery (CSRF) attacks.");

  script_tag(name:"affected", value:"Zikula version prior to 1.2.3");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit( 0 );

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"1.2.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.2.3", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);