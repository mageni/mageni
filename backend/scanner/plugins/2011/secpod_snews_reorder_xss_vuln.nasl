###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_snews_reorder_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# sNews 'reorder' Functions Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = 'cpe:/a:solucija:snews';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902544");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_cve_id("CVE-2011-2706");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("sNews 'reorder' Functions Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Jul/296");
  script_xref(name:"URL", value:"http://security.bkis.com/snews-1-7-1-xss-vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_snews_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to insert arbitrary
  HTML and script code, which will be executed in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"sNews Version 1.7.1");
  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  via 'reorder' functions of administrator, which allows attackers to execute
  arbitrary HTML and script code on the web server.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running sNews and is prone to cross site scripting
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if(version_is_equal(version:vers, test_version:"1.7.1")) {
  security_message(port:port);
  exit(0);
}

exit(99);