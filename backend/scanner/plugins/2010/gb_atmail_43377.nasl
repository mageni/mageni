###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atmail_43377.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Atmail 'MailType' Parameter Cross Site Scripting Vulnerability
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

CPE = "cpe:/a:atmail:atmail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100818");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-22 16:24:51 +0200 (Wed, 22 Sep 2010)");
  script_bugtraq_id(43377);
  script_cve_id("CVE-2010-4930");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Atmail 'MailType' Parameter Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43377");
  script_xref(name:"URL", value:"http://atmail.com/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/513890");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("atmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Atmail/installed");

  script_tag(name:"solution", value:"Reports indicate that this issue has been fixed by the vendor, this has
  not been confirmed. Please contact the vendor for more information.");

  script_tag(name:"summary", value:"Atmail is prone to a cross-site scripting vulnerability because it fails
  to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary JavaScript code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker to
  steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Atmail 6.1.9 is vulnerable. Prior versions may also be affected.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:port)) exit(0);

if(version_is_less(version: vers, test_version: "6.2.0")) {
  security_message(port:port);
  exit(0);
}

exit(0);