###############################################################################
# OpenVAS Vulnerability Test
# $Id: testlink_37258.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# TestLink Cross Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
CPE = "cpe:/a:teamst:testlink";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100390");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-12-10 18:09:58 +0100 (Thu, 10 Dec 2009)");
  script_bugtraq_id(37258);
  script_cve_id("CVE-2009-4237", "CVE-2009-4238");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("TestLink Cross Site Scripting and SQL Injection Vulnerabilities");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("testlink_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("testlink/installed");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"TestLink is prone to multiple SQL-injection and cross-site scripting
  vulnerabilities because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to steal cookie-based authentication
  credentials, compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Versions prior to TestLink 1.8.5 are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37258");
  script_xref(name:"URL", value:"http://www.teamst.org/index.php?option=com_content&task=view&id=84&Itemid=2");
  script_xref(name:"URL", value:"http://www.teamst.org/");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/testlink-multiple-injection-vulnerabilities");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version: vers, test_version: "1.8.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.8.5");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);