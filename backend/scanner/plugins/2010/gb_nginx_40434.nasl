###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nginx_40434.nasl 13859 2019-02-26 05:27:33Z ckuersteiner $
#
# nginx Space String Remote Source Code Disclosure Vulnerability
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

CPE = "cpe:/a:nginx:nginx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100658");
  script_version("$Revision: 13859 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 06:27:33 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-05-31 18:31:53 +0200 (Mon, 31 May 2010)");
  script_bugtraq_id(40434);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("nginx Space String Remote Source Code Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40434");
  script_xref(name:"URL", value:"http://nginx.org/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("nginx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nginx/installed");

  script_tag(name:"solution", value:"Reportedly, the issue is fixed in version 0.8.36. Please contact the
vendor for more information.");

  script_tag(name:"summary", value:"nginx is prone to a remote source code-disclosure vulnerability
because it fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to view the source code of files in the context of the server process,
which may aid in further attacks.

This issue affects nginx versions prior to 0.8.36.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version:"0.8.36")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.8.36");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
