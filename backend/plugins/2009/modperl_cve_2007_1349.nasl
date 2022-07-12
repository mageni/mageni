###############################################################################
# OpenVAS Vulnerability Test
#
# Mod_Perl Path_Info Remote Denial Of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100162");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-04-24 20:04:08 +0200 (Fri, 24 Apr 2009)");
  script_bugtraq_id(23192);
  script_cve_id("CVE-2007-1349");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Mod_Perl Path_Info Remote Denial Of Service Vulnerability");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("modperl_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mod_perl/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"According to its version number, the remote version of the Apache
  mod_perl module is prone to a remote denial-of-service vulnerability.");

  script_tag(name:"impact", value:"Successful exploits may allow remote attackers to cause
  denial-of-service conditions on the webserver running the mod_perl module.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23192");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!version = get_kb_item(string("www/", port, "/mod_perl")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^([0-9.]+)$"))exit(0);

vers = matches[1];

if(!isnull(vers)) {
  if(
     version_is_equal(version: vers, test_version: "2.0.3") ||
     version_is_equal(version: vers, test_version: "2.0.2") ||
     version_is_equal(version: vers, test_version: "2.0.1") ||
     version_is_equal(version: vers, test_version: "1.29")  ||
     version_is_equal(version: vers, test_version: "1.27")  ||
     version_is_equal(version: vers, test_version: "1.99")
    )
  {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
