##############################################################################
# OpenVAS Vulnerability Test
#
# Pecio CMS 'template' Multiple Remote File Include Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.801444");
  script_version("2019-05-16T08:02:32+0000");
  script_tag(name:"last_modification", value:"2019-05-16 08:02:32 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_cve_id("CVE-2010-3204");
  script_bugtraq_id(42806);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Pecio CMS 'template' Multiple Remote File Include Vulnerabilities");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61433");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14815/");
  script_xref(name:"URL", value:"http://eidelweiss-advisories.blogspot.com/2010/08/pecio-cms-v205-template-multiple-remote.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pecio_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("pecio_cms/detected");

  script_tag(name:"insight", value:"The flaw is due to an error in the 'post.php', 'article.php',
  'blog.php' and 'home.php', which are not properly validating the input
  data supplied to 'template' parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Pecio CMS and is prone to multiple
  remote file inclusion vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow the remote attacker to obtain
  sensitive information or to execute malicious PHP code in the context of the webserver process.");

  script_tag(name:"affected", value:"Pecio CMS version 2.0.5");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

cmsPort = get_http_port(default:80);

cmsVer = get_version_from_kb(port:cmsPort, app:"Pecio_CMS");
if(cmsVer)
{
  if(version_is_equal(version:cmsVer, test_version:"2.0.5")){
    security_message(cmsPort);
  }
}
