###############################################################################
# OpenVAS Vulnerability Test
#
# F-Secure Internet Gatekeeper Log File Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.103082");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-02-21 13:57:38 +0100 (Mon, 21 Feb 2011)");
  script_bugtraq_id(46381);
  script_cve_id("CVE-2011-0453");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("F-Secure Internet Gatekeeper Log File Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46381");
  script_xref(name:"URL", value:"https://europe.f-secure.com/products/fsigkl/");
  script_xref(name:"URL", value:"http://www.f-secure.com/en_EMEA/support/security-advisory/fsc-2011-1.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_fsecure_internet_gatekeeper_detect.nasl");
  script_require_ports("Services/www", 9012);
  script_mandatory_keys("f_secure_internet_gatekeeper/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"F-Secure Internet Gatekeeper is prone to an information-disclosure
  vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to gain access to sensitive
  information. Information obtained may lead to other attacks.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:9012);

if(!dir =  get_dir_from_kb(port:port,app:"f_secure_internet_gatekeeper"))exit(0);
url = string(dir, "/fsecure/log/fssp.log");

if(http_vuln_check(port:port, url:url,pattern:"F-Secure Security Platform",extra_check:make_list("Database version:","Starting ArchiveScanner engine"))) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);