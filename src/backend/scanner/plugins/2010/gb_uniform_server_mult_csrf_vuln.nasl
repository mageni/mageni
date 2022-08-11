##############################################################################
# OpenVAS Vulnerability Test
#
# Uniform Server Multiple Cross-Site Request Forgery Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800787");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)");
  script_cve_id("CVE-2010-2113");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_name("Uniform Server Multiple Cross-Site Request Forgery Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39913");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58844");
  script_xref(name:"URL", value:"http://cross-site-scripting.blogspot.com/2010/05/uniform-server-565-xsrf.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_uniform_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("uniform-server/detected");

  script_tag(name:"insight", value:"The application allows users to perform certain actions via HTTP
  requests without performing any validity checks to verify the requests.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Uniform Server and is prone to multiple
  Cross-Site Request Forgery vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to change the
  administrator's password by tricking a logged in administrator into visiting a malicious web site.");

  script_tag(name:"affected", value:"Uniform Server version 5.6.5 and prior.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

uniPort = get_http_port(default:80);

uniVer = get_kb_item("www/" + uniPort + "/Uniform-Server");
if(!uniVer)
  exit(0);

version = eregmatch(pattern:"([0-9.]+)", string:uniVer);
if(!isnull(version[1]))
{
  if(version_is_less_equal(version:version[1], test_version:"5.6.5")){
    security_message(uniPort);
  }
}
