###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_livezilla_mult_xss_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# LiveZilla Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800418");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4450");
  script_name("LiveZilla Multiple Cross-Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37990");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_livezilla_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"LiveZilla Version 3.1.8.3 and prior on all running platform.");
  script_tag(name:"insight", value:"Input passed to the 'lat', 'lng', and 'zom' parameters in 'map.php' is not
  properly sanitised before being returned to the user.");
  script_tag(name:"summary", value:"The host is running LiveZilla and is prone to Cross-Site Scripting
  Vulnerabilities.");
  script_tag(name:"solution", value:"Apply patch  *****
  NOTE : Ignore this warning, if above mentioned patch is applied already.
  *****");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/508613/100/0/threaded");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");


if(!lzPort = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:lzPort)) exit(0);

if(version_is_less_equal(version:vers, test_version:"3.1.8.3")){
  security_message(port:lzPort);
  exit(0);
}

exit(99);