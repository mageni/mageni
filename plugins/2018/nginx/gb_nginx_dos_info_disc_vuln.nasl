###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nginx_dos_info_disc_vuln.nasl 13455 2019-02-05 07:38:02Z mmartin $
#
# nginx 1.1.3 - 1.15.5 Denial of Service and Memory Disclosure via mp4 module
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112420");
  script_version("$Revision: 13455 $");
  script_cve_id("CVE-2018-16845");
  script_bugtraq_id(105868);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 08:38:02 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-11-12 12:06:11 +0100 (Mon, 12 Nov 2018)");

  script_name("nginx 1.1.3 - 1.15.5 Denial of Service and Memory Disclosure via mp4 module");

  script_tag(name:"summary", value:"A security issue was identified in the ngx_http_mp4_module, which might
  allow an attacker to cause infinite loop in a worker process, cause a
  worker process crash, or might result in worker process memory
  disclosure by using a specially crafted mp4 file.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The issue only affects nginx if it is built with the ngx_http_mp4_module
  (the module is not built by default) and the 'mp4' directive is used in
  the configuration file.  Further, the attack is only possible if an
  attacker is able to trigger processing of a specially crafted mp4 file
  with the ngx_http_mp4_module.");

  script_tag(name:"affected", value:"nginx versions 1.1.3 through 1.15.5.");

  script_tag(name:"solution", value:"Upgrade nginx to version 1.15.6.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"http://mailman.nginx.org/pipermail/nginx-announce/2018/000221.html");

  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("nginx_detect.nasl");
  script_mandatory_keys("nginx/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

CPE = "cpe:/a:nginx:nginx";

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:port)) exit(0);

if(version_in_range(version:vers, test_version:"1.1.3", test_version2:"1.15.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.15.6");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
