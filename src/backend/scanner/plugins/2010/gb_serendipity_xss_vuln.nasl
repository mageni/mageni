###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_serendipity_xss_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Serendipity 'serendipity_admin.php' Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
CPE = "cpe:/a:s9y:serendipity";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801517");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_cve_id("CVE-2010-2957");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Serendipity 'serendipity_admin.php' Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/08/29/3");
  script_xref(name:"URL", value:"http://blog.s9y.org/archives/223-Serendipity-1.5.4-released.html");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/xss_vulnerability_in_serendipity.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("serendipity_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Serendipity/installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to steal cookie-based
  authentication credentials, disclosure or modification of sensitive data.");
  script_tag(name:"affected", value:"Serendipity prior to 1.5.4 and on all platforms.");
  script_tag(name:"insight", value:"The flaw exists due to failure in the 'include/functions_entries.inc.php'
  script to properly sanitize user-supplied input in 'serendipity[body]'
  variable.");
  script_tag(name:"solution", value:"Upgrade to Serendipity version 1.5.4 or later.");
  script_tag(name:"summary", value:"This host is running Serendipity and is prone to cross site scripting
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.s9y.org/12.html");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

serPort =  get_app_port(cpe:CPE);
if(!serPort){
  exit(0);
}

if(vers = get_app_version(cpe:CPE, port:serPort))
{
  if(version_is_less(version:vers, test_version:"1.5.4")){
    security_message(serPort);
  }
}
