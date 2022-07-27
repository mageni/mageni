###############################################################################
# OpenVAS Vulnerability Test
#
# Ziproxy Image Parsing Multiple Integer Overflow Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100650");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2010-05-25 13:42:13 +0200 (Tue, 25 May 2010)");
  script_bugtraq_id(40344);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-1513");

  script_name("Ziproxy Image Parsing Multiple Integer Overflow Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40344");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-75/");
  script_xref(name:"URL", value:"http://ziproxy.sourceforge.net/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_ziproxy_server_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("Ziproxy/installed");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Ziproxy is prone to multiple integer-overflow vulnerabilities because
  it fails to properly validate user-supplied data.");

  script_tag(name:"impact", value:"Successful exploits may allow attackers to execute arbitrary code in
  the context of the application. Failed exploit attempts will likely result in denial-of-service conditions.");

  script_tag(name:"affected", value:"Ziproxy 3.0 is vulnerable, other versions may also be affected.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:8080);

if(!vers = get_kb_item(string("www/",port,"/Ziproxy")))exit(0);

if(version_is_equal(version: vers, test_version: "3.0")) {
  security_message(port:port);
  exit(0);
}

exit(0);