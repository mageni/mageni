###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongodb_info_disc_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# MongoDB Information Disclosure Vulnerability
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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

CPE = "cpe:/a:mongodb:mongodb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805730");
  script_version("$Revision: 11872 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-07-24 11:51:27 +0530 (Fri, 24 Jul 2015)");
  script_name("MongoDB Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"The host is installed with MongoDB
  and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as mongodb does not have
  a 'bind_ip 127.0.0.1' option set in the mongodb.conf.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"MongoDB version 2.4.x, 2.6.x");

  script_tag(name:"solution", value:"Upgrade mongodb configuration file.");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://blog.shodan.io/its-the-data-stupid");
  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-4216");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Databases");
  script_dependencies("gb_mongodb_webadmin_detect.nasl");
  script_require_ports("Services/mongodb", 28017);
  script_mandatory_keys("mongodb/webadmin/port");
  script_xref(name:"URL", value:"http://www.mongodb.org");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

http_port = get_kb_item('mongodb/webadmin/port');
if(!http_port){
  exit(0);
}

if(http_vuln_check(port:http_port, url:"/", check_header:TRUE,
   pattern:">mongod", extra_check:make_list("BOOST_LIB_VERSION",
    "databases", "db version")))
{
  security_message(http_port);
  exit(0);
}
