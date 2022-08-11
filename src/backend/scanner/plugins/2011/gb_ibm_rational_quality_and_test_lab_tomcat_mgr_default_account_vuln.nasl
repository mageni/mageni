##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_rational_quality_and_test_lab_tomcat_mgr_default_account_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# IBM Rational Quality Manager and Rational Test Lab Manager Tomcat Default Account Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800193");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-20 07:52:11 +0100 (Thu, 20 Jan 2011)");
  script_cve_id("CVE-2010-4094");
  script_bugtraq_id(44172);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("IBM Rational Quality Manager and Rational Test Lab Manager Tomcat Default Account Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41784");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-214");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Oct/1024601.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 9080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in
  the context of an affected application.");

  script_tag(name:"affected", value:"Versions prior  to IBM Rational Quality Manager and IBM Test Lab
  Manager 7.9.0.3 build:1046");

  script_tag(name:"insight", value:"The flaw exists within the installation of the bundled Tomcat server.
  The default ADMIN account is improperly disabled within 'tomcat-users.xml'
  with default password. A remote attacker can use this vulnerability to
  execute arbitrary code under the context of the Tomcat server.");

  script_tag(name:"solution", value:"Upgrade to version 7.9.0.3 build 1046 or higher");

  script_tag(name:"summary", value:"The host is running Tomcat server in IBM Rational Quality Manager/
  IBM Rational Test Lab Manager has a default password for the ADMIN account.");

  script_xref(name:"URL", value:"https://www.ibm.com/developerworks/rational/products/testmanager");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:9080);

host = http_host_name(port:port);

req = string ( "GET /manager/html HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Authorization: Basic QURNSU46QURNSU4=\r\n",
               "\r\n"
             );
res = http_keepalive_send_recv(port:port, data:req);

if(ereg(pattern:"^HTTP/1\.[01] 200", string:res) && "IBM Corporation" >< res &&
   ( "deployConfig" >< res || "installConfig" >< res ) &&
   ("deployWar" >< res || "installWar" >< res))
{
  security_message(port:port);
}

exit(99);