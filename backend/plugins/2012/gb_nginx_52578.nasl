###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nginx_52578.nasl 13859 2019-02-26 05:27:33Z ckuersteiner $
#
# nginx 'ngx_cpystrn()' Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:nginx:nginx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103469");
  script_bugtraq_id(52578);
  script_cve_id("CVE-2012-1180");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_version("$Revision: 13859 $");

  script_name("nginx 'ngx_cpystrn()' Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52578");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=803856");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Mar/65");
  script_xref(name:"URL", value:"http://nginx.org/");
  script_xref(name:"URL", value:"http://trac.nginx.org/nginx/changeset/4530/nginx");

  script_tag(name:"last_modification", value:"$Date: 2019-02-26 06:27:33 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-04-17 10:03:32 +0200 (Tue, 17 Apr 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("nginx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nginx/installed");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"nginx is prone to an information-disclosure vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to harvest sensitive information that
may lead to further attacks.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^1\.1") {
  if(version_is_less(version:version, test_version:"1.1.17")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.1.17");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^1\.0") {
  if (version_is_less(version:version, test_version:"1.0.14")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.0.14");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
