###############################################################################
# OpenVAS Vulnerability Test
#
# Cherokee Web Server Malformed Packet Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################


if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100318");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-10-28 11:13:14 +0100 (Wed, 28 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-4587");
  script_bugtraq_id(36814);

  script_name("Cherokee Web Server Malformed Packet Remote Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36814");
  script_xref(name:"URL", value:"http://www.alobbs.com/modules.php?op=modload&name=cherokee&file=index");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/507456");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Cherokee/banner");

  script_tag(name:"summary", value:"Cherokee Web Server is prone to a remote denial-of-service
  vulnerability.");

  script_tag(name:"impact", value:"An attacker could exploit this issue to crash the affected
  application, denying service to legitimate users.");

  script_tag(name:"affected", value:"Cherokee Web Server 0.5.4 is vulnerable, other versions may also
  be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port: port);
if(!banner)exit(0);

if("Cherokee" >< banner) {

   if(!version = eregmatch(pattern:"Server: Cherokee/([0-9.]+)", string:banner))exit(0);
   vers = version[1];

   if(!isnull(vers)) {
     if(version_is_equal(version: vers,test_version:"0.5.4"))  {
          security_message(port:port);
          exit(0);
     }
   }
 }

exit(0);
