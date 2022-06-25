##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_xwork_info_disc_vuln.nasl 12006 2018-10-22 07:42:16Z mmartin $
#
# Apache Struts2 'XWork' Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:apache:struts";
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801940");
  script_version("$Revision: 12006 $");
  script_cve_id("CVE-2011-2088");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 09:42:16 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Apache Struts2 'XWork' Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is running Apache Struts and is
  prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted SNMP request and
  check whether it is able read the sensitive information");

  script_tag(name:"insight", value:"The flaw is due to error in XWork, when handling
  the 's:submit' element and a nonexistent method, which gives sensitive information
  about internal Java class paths.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain potentially sensitive
  information about internal Java class paths via vectors involving an s:submit
  element and a nonexistent method, .");

  script_tag(name:"affected", value:"XWork version 2.2.1 in Apache Struts 2.2.1");

  script_tag(name:"solution", value:"Upgrade to Struts version 2.2.3 or later");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/WW-3579");
  script_xref(name:"URL", value:"http://www.ventuneac.net/security-advisories/MVSA-11-006");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_apache_struts2_detection.nasl");
  script_mandatory_keys("ApacheStruts/installed");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  script_xref(name:"URL", value:"http://struts.apache.org/download.cgi");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
 exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:port))
{
  exit(0);
}

req = http_get(item:string(dir,"/example/HelloWorld.action"), port:port);
res = http_keepalive_send_recv(port:port, data:req);

if("<title>Struts" >< res)
{
  req = http_get(item:string(dir,"/Nonmethod.action"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ##  Confirm the exploit
  if("Stacktraces" >< res &&  "Nonmethod" >< res)
  {
    security_message(port);
    exit(0);
  }
}
