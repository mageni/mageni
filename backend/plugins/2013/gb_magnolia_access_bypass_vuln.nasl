###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_magnolia_access_bypass_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Magnolia CMS Access Bypass Vulnerability
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803679");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-4621");
  script_bugtraq_id(60761);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-07-01 10:09:04 +0530 (Mon, 01 Jul 2013)");
  script_name("Magnolia CMS Access Bypass Vulnerability");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Jun/202");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/magnolia-cms-458-access-bypass");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
  restrictions, obtain sensitive information and perform unauthorized actions.");
  script_tag(name:"affected", value:"Magnolia CMS version 4.5.8 and prior");
  script_tag(name:"insight", value:"The flaw allows non-administrator users to view contents from
  magnoliaPublic/.magnolia/log4j, /pages/logViewer.html,
  /pages/configuration.html, /pages/sendMail.html, /pages/permission.html,
  /pages/installedModulesList.html, and /pages/jcrUtils.html pages.");
  script_tag(name:"solution", value:"Upgrade to Magnolia CMS 4.5.9 or later.");
  script_tag(name:"summary", value:"This host is running Magnolia CMS and is prone to access bypass
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.magnolia-cms.com");
  exit(0);
}

include("http_func.inc");

include("host_details.inc");

port = get_http_port(default:8080);

req = http_get(item:string("/magnoliaPublic/.magnolia/pages/adminCentral.html"), port:port);
res = http_send_recv(port:port, data:req);

if(">Magnolia" >< res && ">Magnolia International Ltd" >< res)
{

  host = http_host_name(port:port);

  url = "/magnoliaPublic/.magnolia/pages/installedModulesList.html ";
  Postdata = "mgnlUserId=eric&mgnlUserPSWD=eric";
  sndReq = string("POST ", url, " HTTP/1.1\r\n",
                  "Host: ", host,"\r\n",
                  "Referer: http://", host, url, "\r\n",
                  "Content-Type: application/x-www-form-urlencoded\r\n",
                  "Content-Length: ",strlen(Postdata), "\r\n\r\n",
                  Postdata);

  rcvRes = http_send_recv(port:port, data:sndReq);

  if(rcvRes && ">Installed modules" >< rcvRes && "Name" >< rcvRes &&
               "Description" >< rcvRes)
  {
    security_message(port:port);
    exit(0);
  }
}
