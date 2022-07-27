###############################################################################
# OpenVAS Vulnerability Test
#
# Apache mod_perl 'Apache::Status' and 'Apache2::Status' Cross Site
# Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100130");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-04-13 18:06:40 +0200 (Mon, 13 Apr 2009)");
  script_bugtraq_id(34383);
  script_cve_id("CVE-2009-0796");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("Apache mod_perl 'Apache::Status' and 'Apache2::Status' Cross Site Scripting Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("modperl_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mod_perl/detected");

  script_tag(name:"solution", value:"The vendor has released a fix through the SVN repository.");

  script_tag(name:"summary", value:"According to its version number, the remote version of the Apache
  mod_perl module is prone to a cross-site scripting vulnerability
  because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the
  affected site. This may allow the attacker to steal cookie-based
  authentication credentials and to launch other attacks.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34383");
  script_xref(name:"URL", value:"http://mail-archives.apache.org/mod_mbox/perl-advocacy/200904.mbox/<ad28918e0904011458h273a71d4x408f1ed286c9dfbc@mail.gmail.com>");
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
     version_is_equal(version: vers, test_version: "1.99") ||
     version_is_equal(version: vers, test_version: "1.3")  ||
     version_is_equal(version: vers, test_version: "1.27") ||
     version_is_equal(version: vers, test_version: "1.29") ||
     version_in_range(version: vers, test_version: "2.0", test_version2:"2.0.4 "))
  {
    security_message(port:port, data:"The target host was found to be vulnerable.");
    exit(0);
  }
}

exit(99);
