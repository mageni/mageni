###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_glassfish_server_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Oracle GlassFish Server Cross-Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = 'cpe:/a:oracle:glassfish_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902456");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_cve_id("CVE-2011-2260");
  script_bugtraq_id(48797);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle GlassFish Server Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17551/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/518923");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103167/SOS-11-009.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web Servers");
  script_dependencies("GlassFish_detect.nasl");
  script_mandatory_keys("GlassFish/installed");
  script_require_ports("Services/www", 8080);

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary HTML and
script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Oracle GlassFish Server version 2.1.1");

  script_tag(name:"insight", value:"The flaw is due to error in the handling of log viewer, which fails to
securely output encode logged values. An unauthenticated attacker can trigger the application to log a malicious
string by entering the values into the username field.");

  script_tag(name:"solution", value:"Apply the security updates.");

  script_tag(name:"summary", value:"The host is running GlassFish Server and is prone to cross-site scripting
vulnerability.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version:"2.1.1")) {
  security_message(port:port);
  exit(0);
}

exit(99);
