###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_mult_xss_n_sql_inj_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# ownCloud Multiple XSS and SQL Injection Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804412");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-1893", "CVE-2013-1890");
  script_bugtraq_id(58855, 58852);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-03-14 13:43:56 +0530 (Fri, 14 Mar 2014)");
  script_name("ownCloud Multiple XSS and SQL Injection Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with ownCloud and is prone to multiple XSS and SQL
injection vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"- Input passed via the 'new_name' POST parameter to
   /apps/bookmarks/ajax/renameTag.php is not properly sanitised before
   being used.

  - Certain unspecified input passed to some files in apps/contacts/ajax/ is not
   properly sanitised before being used.

  - Certain unspecified input passed to addressbookprovider.php is not properly
   sanitised before being used in a SQL query.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to inject or manipulate
SQL queries in the back-end database or conduct script insertion.");
  script_tag(name:"affected", value:"ownCloud Server before version 5.0.1");
  script_tag(name:"solution", value:"Upgrade to ownCloud version 5.0.1 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52833");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/83253");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-012");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl");
  script_mandatory_keys("owncloud/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ownPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ownVer = get_app_version(cpe:CPE, port:ownPort)){
  exit(0);
}

if(version_is_less(version:ownVer, test_version:"5.0.1"))
{
  security_message(port:ownPort);
  exit(0);
}
