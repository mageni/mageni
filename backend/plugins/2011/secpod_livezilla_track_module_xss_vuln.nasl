###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_livezilla_track_module_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# LiveZilla 'Track' Module 'server.php' Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:livezilla:livezilla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901172");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-03 16:00:43 +0100 (Mon, 03 Jan 2011)");
  script_cve_id("CVE-2010-4276");
  script_bugtraq_id(45586);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("LiveZilla 'Track' Module 'server.php' Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/Dec/650");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3331");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_livezilla_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"LiveZilla version 3.2.0.2");
  script_tag(name:"insight", value:"The flaw is caused by an input validation error in the 'server.php'
  script when processing user-supplied data, which could be exploited by attackers
  to cause arbitrary scripting code to be executed by the user's browser in the
  security context of an affected site.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running LiveZilla and is prone to Cross-Site Scripting
  vulnerability.");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:port)){
  exit(0);
}

if( dir == "/" ) dir = "";

url = dir+ '/server.php?request=track&livezilla=<script>alert(\'xss\')</script>';

if(http_vuln_check(port:port, url:url, pattern:"&lt;script&gt;alert\('xss'\)" +
                   "&lt;/script&gt", check_header: TRUE))
{
  security_message(port:port);
  exit(0);
}

exit(99);
