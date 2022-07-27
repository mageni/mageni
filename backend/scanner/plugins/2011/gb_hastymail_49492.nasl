###############################################################################
# OpenVAS Vulnerability Test
#
# Hastymail2 Multiple Cross Site Scripting Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.103244");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-09-08 12:04:18 +0200 (Thu, 08 Sep 2011)");
  script_bugtraq_id(49492);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Hastymail2 Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49492");
  script_xref(name:"URL", value:"http://www.hastymail.org/");
  script_xref(name:"URL", value:"http://hastymail.svn.sourceforge.net/viewvc/hastymail/trunk/hastymail2/CHANGES?revision=1983");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_hastymail2_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hastymail2/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Hastymail2 is prone to multiple cross-site scripting vulnerabilities
  because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may allow the attacker to steal cookie-based authentication
  credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Versions prior to Hastymail2 1.1 RC1 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(vers = get_version_from_kb(port:port,app:"Hastymail2")) {
  if(version_is_less(version: vers, test_version: "1.1 RC1")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
