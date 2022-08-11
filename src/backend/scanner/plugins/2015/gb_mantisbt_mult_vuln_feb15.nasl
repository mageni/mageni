###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantisbt_mult_vuln_feb15.nasl 12818 2018-12-18 09:55:03Z ckuersteiner $
#
# MantisBT Multiple Vulnerabilities - Feb15
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805267");
  script_version("$Revision: 12818 $");
  script_cve_id("CVE-2014-9573", "CVE-2014-9572", "CVE-2014-9571", "CVE-2014-9624");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2015-02-03 17:35:43 +0530 (Tue, 03 Feb 2015)");

  script_name("MantisBT Multiple Vulnerabilities - Feb15");

  script_tag(name:"summary", value:"This host is installed with MantisBT
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Insufficient filtration of input data passed via the 'admin_username' and
  'admin_password' HTTP GET parameters to '/install.php' script.

  - Insufficient access restrictions to the installation script 'install.php'
  when HTTP GET 'install' parameter is set to '4'.

  - One can get an unlimited amount of 'samples' with different perturbations
    for the same challenge.

  - Insufficient filtration of the 'MANTIS_MANAGE_USERS_COOKIE' HTTP COOKIE in
  '/manage_user_page.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server, access the installation
  script and obtain database access credentials and conduct SQL injection attacks.");

  script_tag(name:"affected", value:"MantisBT version before 1.2.19 and 1.3.x
  before 1.3.0-beta.2");

  script_tag(name:"solution", value:"Upgrade to MantisBT version 1.2.19 or
  1.3.0-beta.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2015/q1/156");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2015/q1/158");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2015/q1/157");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/100209");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/100210");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/100211");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23243");
  script_xref(name:"URL", value:"https://www.mantisbt.org/bugs/view.php?id=17937");
  script_xref(name:"URL", value:"https://www.mantisbt.org/bugs/view.php?id=17984");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

##Before 1.2.19
if(version_is_less(version:manVer, test_version:"1.2.19")) {
  fix = "1.2.19";
  VULN = TRUE;
}

##1.3.x before 1.3.0-beta.2
if(version_is_equal(version:manVer, test_version:"1.3.0-beta.1")) {
  fix = "1.3.0-beta.2";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version: manVer, fixed_version: fix);
  security_message(port:manPort, data:report);
  exit(0);
}

exit(99);
