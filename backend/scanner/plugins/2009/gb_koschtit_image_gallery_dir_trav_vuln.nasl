###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_koschtit_image_gallery_dir_trav_vuln.nasl 14325 2019-03-19 13:35:02Z asteins $
#
# KoschtIT Image Gallery Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800803");
  script_version("$Revision: 14325 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:35:02 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-05-22 08:49:17 +0200 (Fri, 22 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1510");
  script_bugtraq_id(34335);
  script_name("KoschtIT Image Gallery Multiple Directory Traversal Vulnerabilities");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8334");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/378734.php");
  script_xref(name:"URL", value:"http://koschtit.tabere.net/forum/showthread.php?tid=6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary commands to
  retrieve local system related files and gain sensitive information.");
  script_tag(name:"affected", value:"KoschtIT Image Gallery version 1.82 and prior.");
  script_tag(name:"insight", value:"Improper validation check while processing user supplied input in the file
  parameter for the files 'ki_makepic.php' and 'ki_nojsdisplayimage.php' under
  ki_base directory.");
  script_tag(name:"solution", value:"Upgrade to KoschtIT Image Gallery version 2.0 Beta 1.");
  script_tag(name:"summary", value:"This host is running KoschtIT Image Gallery and is prone to multiple
  Directory Traversal vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

koschITPort = get_http_port(default:80);

if(!can_host_php(port:koschITPort)){
  exit(0);
}

foreach dir (make_list_unique("/kos2", "/koschtit", "/koschtit2", "/", cgi_dirs(port:koschITPort)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item: dir + "/changelog.txt", port:koschITPort);
  rcvRes = http_keepalive_send_recv(port:koschITPort, data:sndReq);

  if("KoschtIT Image Gallery" >< rcvRes)
  {
    # Match for KoschtIT Image Gallery Version
    ver = eregmatch(pattern:"Gallery ([0-9.]+)(beta)?([0-9]+)?", string:rcvRes);
    if(ver[1] != NULL)
    {
      if(ver[1] != NULL && ver[3] != NULL){
        version = ver[1] + "." + ver[3]; # ver[3] points to beta version.
      }
      else
        version = ver[1];
    }

    if(version != NULL)
    {
      if(version_is_less_equal(version:version, test_version:"1.82"))
      {
        security_message(port:koschITPort, data:"The target host was found to be vulnerable.");
        exit(0);
      }
    }
  }
}

exit(99);
