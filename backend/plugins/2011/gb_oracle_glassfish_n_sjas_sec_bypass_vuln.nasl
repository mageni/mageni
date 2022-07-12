###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_glassfish_n_sjas_sec_bypass_vuln.nasl 10833 2018-08-08 10:35:26Z cfischer $
#
# Oracle GlassFish/System Application Server Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Modified by Michael Meyer <michael.meyer@greenbone.net> 25.08.2010
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

CPE = 'cpe:/a:oracle:glassfish_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801926");
  script_version("$Revision: 10833 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-08 12:35:26 +0200 (Wed, 08 Aug 2018) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-0807");
  script_bugtraq_id(47438);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Oracle GlassFish/System Application Server Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("GlassFish_detect.nasl");
  script_mandatory_keys("GlassFish/installed", "GlassFishAdminConsole/port");
  script_require_ports("Services/www", 8080);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47438/discuss");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/cve/CVE-2011-0807");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2011-301950.html");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to execute arbitrary code
  under the context of the application.");

  script_tag(name:"affected", value:"Oracle GlassFish version 2.1, 2.1.1 and 3.0.1 and Oracle Java System
  Application Server 9.1");

  script_tag(name:"insight", value:"The flaw exists in the Web Administration component which listens by default
  on TCP port 4848. When handling a malformed GET request to the administrative interface, the application does not
  properly handle an exception allowing the request to proceed without authentication.");

  script_tag(name:"solution", value:"Apply the security updates.");

  script_tag(name:"summary", value:"The host is running GlassFish/System Application Server and is prone to
  security bypass vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (!port = get_kb_item("GlassFishAdminConsole/port"))
  exit(0);

if (version =~ "^2") {
  url = '/applications/upload.jsf';
  req = string("get ", url, " HTTP/1.1\r\nHost: ",get_host_name(),"\r\n\r\n");
}
else if (version =~ "^3") {
  url = '/common/applications/uploadFrame.jsf';
  req = string("get ", url, " HTTP/1.1\r\nHost: ",get_host_name(),"\r\n\r\n");
}

if(req) {
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if (!isnull(buf)) {
    if (egrep(pattern:"<title>Deploy.*Applications.*Modules</title>", string:buf)) {
      report = report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
