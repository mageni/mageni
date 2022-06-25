###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symphony_cms_dir_trav_vuln.nasl 11553 2018-09-22 14:22:01Z cfischer $
#
# Symphony CMS Directory traversal vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
CPE = "cpe:/a:symphony-cms:symphony_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801220");
  script_version("$Revision: 11553 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 16:22:01 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_cve_id("CVE-2010-2143");
  script_bugtraq_id(40441);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Symphony CMS Directory traversal vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12809/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1005-exploits/symphony-lfi.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symphony_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("symphony/installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to view files and
execute local scripts in the context of the web server process, which may aid
in further attacks.");
  script_tag(name:"affected", value:"Symphony CMS Version 2.0.7");
  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
via the 'mode' parameter in 'index.php' that allows the attackers to view files
and execute local scripts in the context of the web server.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running Symphony CMS and is prone to directory
traversal vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

port = get_app_port(cpe:CPE);
if(!port){
  exit(0);
}

symphonyVer = get_app_version(cpe:CPE, port:port);
if(symphonyVer)
{
  if(version_is_equal(version:symphonyVer, test_version:"2.0.7")) {
    security_message(port);
  }
}
