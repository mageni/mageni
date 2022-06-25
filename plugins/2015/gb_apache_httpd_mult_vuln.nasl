###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_httpd_mult_vuln.nasl 13783 2019-02-20 11:12:24Z cfischer $
#
# Apache HTTP Server Multiple Vulnerabilities May15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805638");
  script_version("$Revision: 13783 $");
  script_cve_id("CVE-2014-3523", "CVE-2014-0118", "CVE-2014-0226", "CVE-2014-0231");
  script_bugtraq_id(73040);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-20 12:12:24 +0100 (Wed, 20 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-05-27 12:15:46 +0530 (Wed, 27 May 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Only vulnerable if mod_lua/mod_deflate/mod_status/mod_cgid is enabled
  script_name("Apache HTTP Server Multiple Vulnerabilities May15");

  script_tag(name:"summary", value:"This host is installed with Apache HTTP Server
  and is prone to denial of service  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Vulnerability in the WinNT MPM component within the 'winnt_accept' function
  in server/mpm/winnt/child.c script that is triggered when the default
  AcceptFilter is used.

  - Vulnerability in the mod_deflate module that is triggered when handling
  highly compressed bodies.

  - A race condition in the mod_status module that is triggered as user-supplied
  input is not properly validated when handling the scoreboard.

  - Vulnerability in the mod_cgid module that is triggered when used to host CGI
  scripts that do not consume standard input.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attackers to bypass intended access restrictions in opportunistic
  circumstances by leveraging multiple Require directives.");

  script_tag(name:"affected", value:"Apache HTTP Server version before 2.4.10.");

  script_tag(name:"solution", value:"Upgrade to version 2.4.10 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  script_xref(name:"URL", value:"http://www.rapid7.com/db/vulnerabilities/apache-httpd-cve-2014-8109");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl");
  script_mandatory_keys("apache/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.apache.org");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!httpd_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!httpd_ver = get_app_version(cpe:CPE, port:httpd_port)){
  exit(0);
}

if(version_in_range(version:httpd_ver, test_version:"2.4.1", test_version2:"2.4.9"))
{
  report = 'Installed version: ' + httpd_ver + '\n' +
           'Fixed version:     ' + "2.4.10" + '\n';
  security_message(data:report, port:httpd_port);
  exit(0);
}
