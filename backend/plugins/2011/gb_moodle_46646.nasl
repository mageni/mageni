###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moodle_46646.nasl 12104 2018-10-25 16:22:27Z asteins $
#
# Moodle Prior to 1.9.11/2.0.2 Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103103");
  script_version("$Revision: 12104 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 18:22:27 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-03 13:33:12 +0100 (Thu, 03 Mar 2011)");
  script_bugtraq_id(46646);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Moodle Prior to 1.9.11/2.0.2 Multiple Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46646");
  script_xref(name:"URL", value:"http://www.moodle.org");
  script_xref(name:"URL", value:"http://moodle.org/mod/forum/discuss.php?d=170002");
  script_xref(name:"URL", value:"http://moodle.org/mod/forum/discuss.php?d=170003");
  script_xref(name:"URL", value:"http://moodle.org/mod/forum/discuss.php?d=170004");
  script_xref(name:"URL", value:"http://moodle.org/mod/forum/discuss.php?d=170006");
  script_xref(name:"URL", value:"http://moodle.org/mod/forum/discuss.php?d=170008");
  script_xref(name:"URL", value:"http://moodle.org/mod/forum/discuss.php?d=170009");
  script_xref(name:"URL", value:"http://moodle.org/mod/forum/discuss.php?d=170010");
  script_xref(name:"URL", value:"http://moodle.org/mod/forum/discuss.php?d=170011");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("moodle/detected");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities, including:

  1. Multiple cross-site scripting issues

  2. Multiple information-disclosure issues

  3. An HTML-injection issue

  4. An insecure permissions issue");

  script_tag(name:"impact", value:"Attackers can exploit these issues to bypass certain security
  restrictions, obtain sensitive information, perform unauthorized
  actions, and compromise the application. Other attacks may also
  be possible.");

  script_tag(name:"affected", value:"These issues affect versions prior to Moodle 1.9.11 and 2.0.2.");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:port)) exit(0);

if(version_in_range(version: vers, test_version: "2",test_version2:"2.0.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.0.2");
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version: vers, test_version: "1.9",test_version2:"1.9.10")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.9.11");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
