###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_http_server_mult_vuln_jun17_win.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Apache HTTP Server Multiple Vulnerabilities June17 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811213");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-7679", "CVE-2017-3169", "CVE-2017-3167");
  script_bugtraq_id(99135, 99134);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-21 17:06:43 +0530 (Wed, 21 Jun 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache HTTP Server Multiple Vulnerabilities June17 (Windows)");

  script_tag(name:"summary", value:"This host is running Apache HTTP Server
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists as,

  - The mod_mime can read one byte past the end of a buffer when sending a malicious
    Content-Type response header.

  - The mod_ssl may dereference a NULL pointer when third-party modules call
    ap_hook_process_connection() during an HTTP request to an HTTPS port.

  - An use of the ap_get_basic_auth_pw() by third-party modules outside of the
    authentication phase may lead to authentication requirements being
    bypassed.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass authentication and perform unauthorized actions, cause
  a denial-of-service condition and gain access to potentially sensitive
  information.");

  script_tag(name:"affected", value:"Apache HTTP Server 2.2.x before 2.2.33 and
  2.4.x before 2.4.26 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apache HTTP Server 2.2.33 or 2.4.26
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2017/q2/509");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_22.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://httpd.apache.org");
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

if(httpd_ver =~ "^2\.4")
{
  if(version_is_less(version:httpd_ver, test_version:"2.4.26")){
    fix = "2.4.26";
  }
}
else if(httpd_ver =~ "^2\.2")
{
  if(version_is_less(version:httpd_ver, test_version:"2.2.33")){
    fix = "2.2.33";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:httpd_ver, fixed_version:fix);
  security_message(data:report, port:httpd_port);
  exit(0);
}
