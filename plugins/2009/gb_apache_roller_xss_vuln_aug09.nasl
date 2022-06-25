##############################################################################
# OpenVAS Vulnerability Test
#
# Apache Roller 'q' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800678");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-08-12 19:54:51 +0200 (Wed, 12 Aug 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_bugtraq_id(33110);
  script_cve_id("CVE-2008-6879");
  script_name("Apache Roller 'q' Parameter Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/31523");
  script_xref(name:"URL", value:"http://roller.apache.org/download.cgi");
  script_xref(name:"URL", value:"http://issues.apache.org/roller/browse/ROL-1766");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_roller_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("ApacheRoller/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject arbitrary
  HTML codes in the context of the affected web application.");

  script_tag(name:"affected", value:"Apache Roller Version 2.x, 3.x and 4.0.");

  script_tag(name:"insight", value:"The issue is due to input validation error in 'q' parameter when performing
  a search. It is not properly sanitised before being returned to the user.");

  script_tag(name:"summary", value:"This host is running Apache Roller and is prone to a Cross Site Scripting
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Apache Roller Version 4.0.1 or later or
  apply the patch via the references.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

rollerPort = get_http_port(default:8080);

rollerVer = get_kb_item("www/" + rollerPort + "/ApacheRoller");
if(!rollerVer)
  exit(0);

if(version_in_range(version:rollerVer, test_version:"2.0", test_version2:"2.3") ||
   version_in_range(version:rollerVer, test_version:"3.0", test_version2:"3.1") ||
   version_is_equal(version:rollerVer, test_version:"4.0")){
   security_message(port:rollerPort, data:"The target host was found to be vulnerable");
   exit(0);
}

exit(99);
