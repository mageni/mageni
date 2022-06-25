###############################################################################
# OpenVAS Vulnerability Test
#
# Xerver Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.100736");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-08-02 19:12:50 +0200 (Mon, 02 Aug 2010)");
  script_bugtraq_id(42110);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Xerver Multiple Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42110");
  script_xref(name:"URL", value:"http://www.javascript.nu/xerver/");
  script_xref(name:"URL", value:"http://spareclockcycles.org/2010/08/01/multiple-vulnerabilities-in-xerver-4-32/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_xerver_http_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("xerver/detected");

  script_tag(name:"summary", value:"Xerver is prone to multiple vulnerabilities including source code
  disclosure, denial of service, security bypass, and directory-traversal issues.");

  script_tag(name:"impact", value:"Successfully exploiting these issues may allow an attacker to disclose
  sensitive information, bypass certain security-restrictions, perform
  denial-of-service attacker or execute arbitrary binaries.");

  script_tag(name:"affected", value:"These issues affect Xerver versions up to and including 4.32.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!vers = get_kb_item(string("www/", port, "/Xerver")))
  exit(0);

if(!isnull(vers) && vers >!< "unknown") {
  if(version_is_less_equal(version:vers,test_version:"4.32")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);