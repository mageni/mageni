###############################################################################
# OpenVAS Vulnerability Test
#
# Phorum Multiple Cross Site Scripting Vulnerabilities
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100164");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-04-24 20:04:08 +0200 (Fri, 24 Apr 2009)");
  script_bugtraq_id(34551);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Phorum Multiple Cross Site Scripting Vulnerabilities");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("phorum_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phorum/detected");

  script_tag(name:"summary", value:"According to its version number, the remote version of Phorum is
  prone to multiple cross-site scripting vulnerabilities because the
  application fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to steal cookie-based
  authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Phorum 5.2.10 and 5.2-dev are vulnerable, other versions may also be
  affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34551");
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
if(!version = get_kb_item(string("www/", port, "/phorum")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "5.2.10") ||
     ereg(pattern:"^5\.2-dev$", string: vers))
  {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
