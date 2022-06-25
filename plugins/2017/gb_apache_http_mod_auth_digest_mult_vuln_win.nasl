###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_http_mod_auth_digest_mult_vuln_win.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Apache HTTP Server 'mod_auth_digest' Multiple Vulnerabilities (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811236");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-9788");
  script_bugtraq_id(99569);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-17 16:02:23 +0530 (Mon, 17 Jul 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache HTTP Server 'mod_auth_digest' Multiple Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"This host is running Apache HTTP Server
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in Apache
  'mod_auth_digest' which does not properly initialize memory used to process
  'Digest' type HTTP Authorization headers.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the target service to crash. A remote user can obtain
  potentially sensitive information as well on the target system.");

  script_tag(name:"affected", value:"Apache HTTP Server 2.2.x before 2.2.34 and
  2.4.x before 2.4.27 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apache HTTP Server 2.2.34 or 2.4.27
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1038906");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_24.html");

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
  if(version_is_less(version:httpd_ver, test_version:"2.4.27")){
    fix = "2.4.27";
  }
}
else if(httpd_ver =~ "^2\.2")
{
  if(version_is_less(version:httpd_ver, test_version:"2.2.34")){
    fix = "2.2.34";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:httpd_ver, fixed_version:fix);
  security_message(data:report, port:httpd_port);
  exit(0);
}
