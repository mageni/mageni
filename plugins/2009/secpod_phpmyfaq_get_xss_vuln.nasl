###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phpmyfaq_get_xss_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# phpMyFAQ GET Variable Cross-Site-Scripting Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = 'cpe:/a:phpmyfaq:phpmyfaq';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900982");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2009-4040");
  script_bugtraq_id(37020);

  script_name("phpMyFAQ GET Variable Cross-Site-Scripting Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  HTML and script code and cause cross-site scripting attacks.");

  script_tag(name:"affected", value:"phpMyFAQ prior to 2.0.17 and 2.5.0 prior to 2.5.2.");

  script_tag(name:"insight", value:"This vulnerability is caused because the application does not properly
  sanitize the input passed into 'GET' parameter in 'search.php'.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to phpMyFAQ 2.0.17 or 2.5.2");

  script_tag(name:"summary", value:"This host is installed with phpMyFAQ and is prone to Cross Site Scripting
  vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37354");
  script_xref(name:"URL", value:"http://www.phpmyfaq.de/advisory_2009-09-01.php");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3241");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version,  test_version: "2.0.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.17");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version,  test_version: "2.5", test_version2: "2.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);