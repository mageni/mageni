###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xampp_writeintolocaldisk_vuln_oct14.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# XAMPP Local Write Access Vulnerability - Oct14
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apachefriends:xampp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804774");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2013-2586");
  script_bugtraq_id(62665);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-10-10 11:43:07 +0530 (Fri, 10 Oct 2014)");

  script_name("XAMPP Local Write Access Vulnerability - Oct14");

  script_tag(name:"summary", value:"This host is installed with XAMPP and is
  prone to arbitrary file download vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and
  check whether it is able to write data into local file or not.");

  script_tag(name:"insight", value:"Flaw is due to /xampp/lang.php script not
  properly handling WriteIntoLocalDisk method (i.e) granting write access to
  the lang.tmp file to unprivileged users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to manipulate the file and execute arbitrary script or HTML code.");

  script_tag(name:"affected", value:"XAMPP version 1.8.1, Prior versions may
  also be affected.");

  script_tag(name:"solution", value:"Upgrade to version 1.8.2 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/87499");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/28654");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123407");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_xampp_detect.nasl");
  script_mandatory_keys("xampp/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://sourceforge.net/projects/xampp");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

## Before Updating lang.tmp get the content in it
## to revert it back after updation
req = http_get(item:string(dir, "/lang.tmp"),  port:http_port);
langtmp = http_keepalive_send_recv(port:http_port, data:req, bodyonly:TRUE);

url = dir + "/lang.php?WriteIntoLocalDisk";

## Send the Request to update lang.tmp
if(http_vuln_check(port:http_port, url:url,
             check_header:FALSE, pattern:"HTTP.*302 Found"))
{
  if(http_vuln_check(port:http_port, url:string(dir, "/lang.tmp"),
               check_header:TRUE, pattern:"WriteIntoLocalDisk"))
  {
    ## Send the Request to update lang.tmp
    if(http_vuln_check(port:http_port, url:string(dir, "/lang.php?", langtmp),
                 check_header:FALSE, pattern:"HTTP.*302 Found"))
    {
      url = string(dir, "/lang.tmp");
      if(http_vuln_check(port:http_port, url:url,
                   check_header:TRUE, pattern:langtmp,
                   check_nomatch:"WriteIntoLocalDisk"))

      {
        report = report_vuln_url(port:http_port, url:url);
        security_message(port:http_port, data:report);
        exit(0);
      }
    }
  }
}
