###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_contact_form_maker_sql_inj_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Joomla Contact Form Maker SQL Injection Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805519");
  script_version("$Revision: 11872 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-04-01 18:13:27 +0530 (Wed, 01 Apr 2015)");
  script_tag(name:"qod_type", value:"remote_vul");

  script_name("Joomla Contact Form Maker SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Joomla Contact Form Maker and is prone to sql
injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and check whether it is able to execute
sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to joomla component Contact Form Maker is not filtering data in
'id' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject or manipulate SQL
queries in the back-end database, allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Joomla Contact Form Maker version 1.0.1");

  script_tag(name:"solution", value:"Upgrade to 1.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36561");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/131163");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://extensions.joomla.org/extensions/extension/contacts-and-feedback/contact-forms/contact-form-maker");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:http_port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?option=com_contactformmaker&view=contactformmaker&"
          + "id=1%27SQL-INJECTION-TEST";

if(http_vuln_check(port:http_port, url:url, pattern:"SQL-INJECTION-TEST",
                   extra_check:"You have an error in your SQL syntax"))
{
  report = report_vuln_url(port: http_port, url: url);
  security_message(port:http_port, data:report);
  exit(0);
}

exit(99);
