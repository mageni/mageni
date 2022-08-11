###############################################################################
# OpenVAS Vulnerability Test
# $Id: sympa_new_list_xss.nasl 10781 2018-08-06 07:41:20Z cfischer $
#
# Sympa New List Cross-Site Scripting Vulnerability
#
# Authors:
# (C) Tenable Network Security based on work from David Maciejak
#
# Copyright:
# Copyright (C) 2004-2008 Tenable Network Security
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80090");
  script_version("$Revision: 10781 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-06 09:41:20 +0200 (Mon, 06 Aug 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2004-1735");
  script_bugtraq_id(10992);
  script_name("Sympa New List Cross-Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004-2008 Tenable Network Security");
  script_family("Web application abuses");
  script_dependencies("sympa_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sympa/detected");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2004-08/0293.html");

  script_tag(name:"solution", value:"Update to version 4.1.3 or newer.");

  script_tag(name:"summary", value:"The remote web server contains a CGI script that is affected by a
  cross-site scripting vulnerability.

  Description :

  According to its version number, the installation of Sympa on the remote host contains an HTML injection
  vulnerability that may allow a user who has the privileges to create a new list to inject HTML tags
  in the list description field.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

install = get_kb_item(string("www/", port, "/sympa"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  ver = matches[1];
  if (ver =~ "^(2\.|3\.|4\.0\.|4\.1\.[012]([^0-9]|$))")
  {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

exit(0);