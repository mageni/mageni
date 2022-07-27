###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_xss_n_code_inj_vuln.nasl 14033 2019-03-07 11:09:35Z cfischer $
#
# Drupal XSS and Code Injection Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800908");
  script_version("$Revision: 14033 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 12:09:35 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-07-15 13:05:34 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2372", "CVE-2009-2373");
  script_bugtraq_id(35548);
  script_name("Drupal XSS and Code Injection Vulnerability");
  script_xref(name:"URL", value:"http://drupal.org/node/507572");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35681");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Jul/1022497.html");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl");
  script_mandatory_keys("drupal/installed");

  script_tag(name:"impact", value:"Attackers can exploit this issue to conduct script insertion attacks and
  inject and execute arbitrary PHP, HTML and script code.");

  script_tag(name:"affected", value:"Drupal version 6.x before 6.13 on all platforms.");

  script_tag(name:"insight", value:"Multiple flaws arise because,

  - The users can modify user signatures after the associated comment format is
  changed to an administrator-controlled input format, which allows remote
  authenticated users to inject arbitrary code via a crafted user signature.

  - When input passed into the unspecified vectors in the Forum module is not
  properly sanitised before being returned to the user.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Drupal 6.13 or later.");

  script_tag(name:"summary", value:"The host is installed with Drupal and is prone to Cross Site Scripting and
  Remote Code Injection vulnerabilities.");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!drPort = get_app_port( cpe:CPE ))
  exit(0);

if( ! drupalVer = get_app_version( cpe:CPE, port:drPort, version_regex:"^[0-9]\.[0-9]+" ) )
  exit( 0 );

if(version_in_range(version:drupalVer, test_version:"6.0", test_version2:"6.12")) {
  report = report_fixed_ver(installed_version:drupalVer, fixed_Version:"6.13");
  security_message(port:drPort, data:report);
  exit(0);
}

exit(99);